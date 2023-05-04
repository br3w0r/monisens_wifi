mod bindings_gen;
mod c_parser;

use bindings_gen as bg;

use std::collections::HashSet;
use std::io::ErrorKind;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::SystemTime;
use std::{
    ffi::{CStr, CString},
    io::{Read, Write},
    net::TcpStream,
    ptr::null,
    time::Duration,
};

use async_macros::select;
use async_std::{
    channel::{self, Receiver, Sender},
    task,
};
use lazy_static::lazy_static;
use libc::c_void;

const THREAD_SLEEP_DURATION: Duration = Duration::from_millis(100);

const CONN_PARAM_IP: &str = "IP Address with port";

const DEV_CONF_ID_SENSOR_COMM_INTERVAL: i32 = 1;

const SENSOR_NAME: &str = "light_temp_humidity";

const SENSOR_DATA_LIGHT: &str = "light";
const SENSOR_DATA_TEMP: &str = "temperature";
const SENSOR_DATA_HUMIDITY: &str = "humidity";
const SENSOR_DATA_TIMESTAMP: &str = "timestamp";

const READ_TIMEOUT: Duration = Duration::from_millis(100);
const WRITE_TIMEOUT: Duration = Duration::from_millis(200);

lazy_static! {
    static ref AVAILABLE_MSG_TYPES: HashSet<u8> = HashSet::from([b':', b'>']);
}

#[no_mangle]
pub extern "C" fn mod_version() -> u8 {
    1
}

pub struct Module {
    client: Option<Arc<Mutex<TcpStream>>>,

    conn_conf: Option<ConnConf>,
    device_conf: Option<DeviceConf>,

    // Process flow
    thread_handle: Option<JoinHandle<()>>,
    stop_tx: Option<Sender<()>>,
}

#[repr(transparent)]
pub struct Handle(*mut c_void);

impl Handle {
    /// # Panics
    /// Panics if `self.0` == null.
    pub unsafe fn as_module(&self) -> &'static mut Module {
        let ptr = self.0 as *mut Module;
        ptr.as_mut().unwrap() // Expect null checks before
    }

    /// # Safety
    /// `self.0` != null.
    pub unsafe fn destroy(&mut self) {
        let ptr = self.0 as *mut Module;
        let _ = Box::from_raw(ptr);
        self.0 = std::ptr::null::<c_void>() as *mut _;
    }

    pub fn from_module(module: Module) -> Self {
        let reference = Box::leak(Box::new(module));
        Self((reference as *mut Module) as _)
    }
}

#[no_mangle]
pub unsafe extern "C" fn functions() -> bg::Functions {
    bg::Functions {
        init: Some(init),
        obtain_device_info: Some(obtain_device_info),
        destroy: Some(destroy),
        connect_device: Some(connect_device),
        obtain_device_conf_info: Some(obtain_device_conf_info),
        configure_device: Some(configure_device),
        obtain_sensor_type_infos: Some(obtain_sensor_type_infos),
        start: Some(start),
        stop: Some(stop),
    }
}

#[no_mangle]
pub unsafe extern "C" fn init(sel: *mut *mut c_void) {
    let m = Module {
        client: None,
        conn_conf: None,
        device_conf: None,
        thread_handle: None,
        stop_tx: None,
    };

    *sel = Handle::from_module(m).0;
}

#[no_mangle]
pub unsafe extern "C" fn obtain_device_info(
    handler: *mut c_void,
    obj: *mut c_void,
    callback: bg::device_info_callback,
) {
    let port_param_name = CString::new(CONN_PARAM_IP).unwrap();

    let params_vec: Vec<bg::ConnParamInfo> = vec![bg::ConnParamInfo {
        name: port_param_name.as_ptr() as _,
        typ: bg::ConnParamType::ConnParamString,
        info: null::<c_void>() as _,
    }];
    let mut conn_info = bg::DeviceConnectInfo {
        connection_params: params_vec.as_ptr() as _,
        connection_params_len: params_vec.len() as _,
    };

    callback.unwrap()(obj, &mut conn_info as _);
}

#[no_mangle]
pub unsafe extern "C" fn destroy(sel: *mut c_void) {
    stop(sel);
    Handle(sel).destroy();
}

const DEVICE_ERROR_NONE: u8 = 0;

#[repr(u8)]
pub enum DeviceErr {
    DeviceErrConn = 1,
    DeviceErrParams = 2,
}

#[no_mangle]
pub extern "C" fn connect_device(handler: *mut c_void, confs: *mut bg::DeviceConnectConf) -> u8 {
    if let Err(err) = connect_device_impl(handler, confs) {
        err as _
    } else {
        DEVICE_ERROR_NONE
    }
}

fn connect_device_impl(
    handler: *mut c_void,
    confs: *mut bg::DeviceConnectConf,
) -> Result<(), DeviceErr> {
    let module = unsafe { Handle(handler).as_module() };
    let conf = ConnConf::new(confs)?;

    let client = TcpStream::connect(&conf.ip).map_err(|_| DeviceErr::DeviceErrConn)?;

    module.client = Some(Arc::new(Mutex::new(client)));
    module.conn_conf = Some(conf);

    Ok(())
}

extern "C" fn obtain_device_conf_info(
    _: *mut c_void,
    obj: *mut c_void,
    callback: bg::device_conf_info_callback,
) {
    let mut entries = Vec::with_capacity(2);

    // ENTRY: Sensor read interval
    let entry_interval_name = CString::new("Sensor read interval (in milliseconds)").unwrap();
    let mut entry_interval_lt = 30000i32;
    let mut entry_interval_gt = 500i32;
    let mut entry_interval_def = 1000i32;
    let mut entry_interval = bg::DeviceConfInfoEntryInt {
        required: true,
        def: &mut entry_interval_def as _,
        lt: &mut entry_interval_lt as _,
        gt: &mut entry_interval_gt as _,
        neq: null::<i32>() as _,
    };
    entries.push(bg::DeviceConfInfoEntry {
        id: DEV_CONF_ID_SENSOR_COMM_INTERVAL,
        name: entry_interval_name.as_ptr() as _,
        typ: bg::DeviceConfInfoEntryType::DeviceConfInfoEntryTypeInt,
        data: &mut entry_interval as *mut bg::DeviceConfInfoEntryInt as *mut c_void,
    });

    let mut conf_info = bg::DeviceConfInfo {
        device_confs: entries.as_ptr() as _,
        device_confs_len: entries.len() as _,
    };

    unsafe { callback.unwrap()(obj, &mut conf_info as _) };
}

#[derive(Debug)]
struct ConnConf {
    ip: String,
}

impl ConnConf {
    fn new(confs_raw: *mut bg::DeviceConnectConf) -> Result<Self, DeviceErr> {
        if confs_raw.is_null() {
            return Err(DeviceErr::DeviceErrParams);
        }

        let confs = unsafe {
            std::slice::from_raw_parts(
                (*confs_raw).connection_params,
                (*confs_raw).connection_params_len as usize,
            )
        };

        let name = (unsafe { CStr::from_ptr(confs[0].name) }.to_str())
            .map_err(|_| DeviceErr::DeviceErrParams)?;
        if confs.len() != 1 || name != CONN_PARAM_IP {
            return Err(DeviceErr::DeviceErrParams);
        }

        let ip = c_parser::as_string(confs[0].value).ok_or(DeviceErr::DeviceErrParams)?;

        Ok(ConnConf { ip })
    }
}

#[derive(Debug)]
struct DeviceConf {
    comm_interval: i32,
}

impl DeviceConf {
    pub fn new(raw: *mut bg::DeviceConf) -> Result<DeviceConf, DeviceErr> {
        let raw_conf = unsafe { std::slice::from_raw_parts((*raw).confs, (*raw).confs_len as _) };

        if raw_conf.len() != 1 || raw_conf[0].id != DEV_CONF_ID_SENSOR_COMM_INTERVAL {
            return Err(DeviceErr::DeviceErrParams);
        }

        Ok(DeviceConf {
            comm_interval: unsafe { *(raw_conf[0].data as *const i32) },
        })
    }
}

extern "C" fn configure_device(handler: *mut c_void, conf: *mut bg::DeviceConf) -> u8 {
    if let Err(err) = configure_device_impl(handler, conf) {
        err as _
    } else {
        DEVICE_ERROR_NONE
    }
}

fn configure_device_impl(handler: *mut c_void, conf: *mut bg::DeviceConf) -> Result<(), DeviceErr> {
    let device_conf = DeviceConf::new(conf)?;
    let module = unsafe { Handle(handler).as_module() };

    let mut client = module
        .client
        .as_ref()
        .ok_or(DeviceErr::DeviceErrConn)?
        .lock()
        .unwrap();

    let msg = format!("d{};", device_conf.comm_interval);
    client
        .write(msg.as_bytes())
        .map_err(|_| DeviceErr::DeviceErrConn)?;

    module.device_conf = Some(device_conf);

    Ok(())
}

extern "C" fn obtain_sensor_type_infos(
    _: *mut c_void,
    obj: *mut c_void,
    callback: bg::sensor_type_infos_callback,
) -> u8 {
    // SENSOR: Test Server
    let type_info_light_name = CString::new(SENSOR_DATA_LIGHT).unwrap();
    let type_info_light = bg::SensorDataTypeInfo {
        name: type_info_light_name.as_ptr() as _,
        typ: bg::SensorDataType::SensorDataTypeInt16,
    };

    let type_info_temp_name = CString::new(SENSOR_DATA_TEMP).unwrap();
    let type_info_temp = bg::SensorDataTypeInfo {
        name: type_info_temp_name.as_ptr() as _,
        typ: bg::SensorDataType::SensorDataTypeFloat32,
    };

    let type_info_humidity_name = CString::new(SENSOR_DATA_HUMIDITY).unwrap();
    let type_info_humidity = bg::SensorDataTypeInfo {
        name: type_info_humidity_name.as_ptr() as _,
        typ: bg::SensorDataType::SensorDataTypeFloat32,
    };

    let type_info_timestamp_name = CString::new(SENSOR_DATA_TIMESTAMP).unwrap();
    let type_info_timestamp = bg::SensorDataTypeInfo {
        name: type_info_timestamp_name.as_ptr() as _,
        typ: bg::SensorDataType::SensorDataTypeTimestamp,
    };

    let sensor_type_info_vec = vec![
        type_info_light,
        type_info_temp,
        type_info_humidity,
        type_info_timestamp,
    ];

    let sensor_name = CString::new(SENSOR_NAME).unwrap();

    // Sensor infos
    let sensor_type_infos_vec = vec![bg::SensorTypeInfo {
        name: sensor_name.as_ptr() as _,
        data_type_infos_len: sensor_type_info_vec.len() as _,
        data_type_infos: sensor_type_info_vec.as_ptr() as _,
    }];

    let sensor_type_infos = bg::SensorTypeInfos {
        sensor_type_infos_len: sensor_type_infos_vec.len() as _,
        sensor_type_infos: sensor_type_infos_vec.as_ptr() as _,
    };

    unsafe { callback.unwrap()(obj, &sensor_type_infos as *const _ as *mut _) };

    DEVICE_ERROR_NONE
}

struct MsgHandle(*mut c_void);

unsafe impl Send for MsgHandle {}

extern "C" fn start(
    handler: *mut c_void,
    msg_handler: *mut c_void,
    handle_func: bg::handle_msg_func,
) -> u8 {
    if let Err(err) = start_impl(handler, msg_handler, handle_func) {
        err as _
    } else {
        DEVICE_ERROR_NONE
    }
}

fn start_impl(
    handler: *mut c_void,
    msg_handler: *mut c_void,
    handle_func: bg::handle_msg_func,
) -> Result<(), DeviceErr> {
    let module = unsafe { Handle(handler).as_module() };

    let handle = MsgHandle(msg_handler);
    let (tx, rx) = channel::bounded(1);

    let client = module
        .client
        .as_ref()
        .ok_or(DeviceErr::DeviceErrConn)?
        .clone();

    let comm_interval = module.device_conf.as_ref().unwrap().comm_interval.clone();

    let t = thread::spawn(move || {
        let msg_processor = MsgProcessor {
            handle_func,
            handle,
        };

        let stop_rx = rx;
        let mut client = client.lock().unwrap();

        {
            client.set_read_timeout(Some(READ_TIMEOUT)).unwrap();
            // clear buffer before start
            let mut buf = [0u8; 32];
            loop {
                let res = client.read(&mut buf);
                if let Err(ref err) = res {
                    if err.kind() == ErrorKind::WouldBlock {
                        break;
                    } else {
                        res.unwrap();
                    }
                }
            }
        }

        client.set_read_timeout(None).unwrap();

        client.write(b"a;").unwrap();

        let mut buf: Vec<u8> = Vec::with_capacity(64);
        loop {
            let mut c = [0u8];
            if client.read(&mut c).unwrap() > 0 {
                match c[0] {
                    b'\n' => {
                        msg_processor.process(buf.drain(..).collect());

                        if !task::block_on(timer_with_cancel(THREAD_SLEEP_DURATION, &stop_rx)) {
                            // Stopping thread
                            client.write(b"i;").unwrap();
                            return;
                        }
                    }
                    val => buf.push(val),
                }
            }
        }
    });

    module.thread_handle = Some(t);
    module.stop_tx = Some(tx);

    Ok(())
}

extern "C" fn stop(handler: *mut ::std::os::raw::c_void) -> u8 {
    let module = unsafe { Handle(handler).as_module() };

    let opt_handle = std::mem::replace(&mut module.thread_handle, None);
    if let Some(handle) = opt_handle {
        task::spawn(async {
            module.stop_tx.as_ref().unwrap().close();
        });

        handle.join().unwrap();
    }

    DEVICE_ERROR_NONE
}

pub struct SensorData {
    light: i16,
    temp: f32,
    humidity: f32,
}

struct MsgProcessor {
    handle_func: bg::handle_msg_func,
    handle: MsgHandle,
}

impl MsgProcessor {
    fn process(&self, msg: Vec<u8>) {
        let sanitized_msg = Self::sanitize_serial_msg(msg);
        if let None = sanitized_msg {
            return;
        }
        let sanitized_msg = sanitized_msg.unwrap();

        let mut msg_iter = sanitized_msg.chars();
        let typ = msg_iter.next().expect("msg from device is empty");
        let msg: String = msg_iter.collect();

        match typ {
            ':' => {
                let sensor_data = Self::format_data_msg(&msg).unwrap();
                self.send_sensor_data(sensor_data);
            }
            _ => panic!("unexpected message from device: {}", msg),
        };
    }

    fn send_sensor_data(&self, data: SensorData) {
        let sensor_timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let type_info_light_name = CString::new(SENSOR_DATA_LIGHT).unwrap();
        let type_info_temp_name = CString::new(SENSOR_DATA_TEMP).unwrap();
        let type_info_humidity_name = CString::new(SENSOR_DATA_HUMIDITY).unwrap();
        let type_info_timestamp_name = CString::new(SENSOR_DATA_TIMESTAMP).unwrap();

        let data = vec![
            bg::SensorMsgData {
                name: type_info_light_name.as_ptr() as _,
                typ: bg::SensorDataType::SensorDataTypeInt16,
                data: &data.light as *const i16 as _,
            },
            bg::SensorMsgData {
                name: type_info_temp_name.as_ptr() as _,
                typ: bg::SensorDataType::SensorDataTypeFloat32,
                data: &data.temp as *const f32 as _,
            },
            bg::SensorMsgData {
                name: type_info_humidity_name.as_ptr() as _,
                typ: bg::SensorDataType::SensorDataTypeFloat32,
                data: &data.humidity as *const f32 as _,
            },
            bg::SensorMsgData {
                name: type_info_timestamp_name.as_ptr() as _,
                typ: bg::SensorDataType::SensorDataTypeTimestamp,
                data: &sensor_timestamp as *const i64 as *mut _,
            },
        ];

        let sensor_name = CString::new(SENSOR_NAME).unwrap();
        let msg = bg::SensorMsg {
            name: sensor_name.as_ptr() as _,
            data: data.as_ptr() as *mut _,
            data_len: data.len() as _,
        };

        let msg_data = bg::Message {
            typ: bg::MessageType::MessageTypeSensor,
            data: &msg as *const bg::SensorMsg as *mut _,
        };

        unsafe { self.handle_func.unwrap()(self.handle.0, msg_data) };
    }

    fn format_data_msg(data: &str) -> Result<SensorData, ()> {
        let parts: Vec<&str> = data.split(';').collect();

        if parts.len() < 3 {
            return Err(());
        }

        let light: i16 = if let Ok(val) = parts[0].parse() {
            Ok(val)
        } else {
            Err(())
        }?;

        let temp: f32 = if let Ok(val) = parts[1].parse() {
            Ok(val)
        } else {
            Err(())
        }?;

        let humidity: f32 = if let Ok(val) = parts[2].parse() {
            Ok(val)
        } else {
            Err(())
        }?;

        Ok(SensorData {
            light,
            temp,
            humidity,
        })
    }

    fn sanitize_serial_msg(mut msg: Vec<u8>) -> Option<String> {
        for (i, ch) in msg.iter().enumerate() {
            if AVAILABLE_MSG_TYPES.contains(ch) {
                return String::from_utf8(msg.drain(i..).collect()).ok();
            }
        }

        None
    }
}

/// Returns `true` if timeout has passed and no message was received from `stop_rx`
async fn timer_with_cancel(dur: Duration, stop_rx: &Receiver<()>) -> bool {
    let sleep_fut = async {
        task::sleep(dur).await;

        true
    };
    let stop_fut = async {
        let _ = stop_rx.recv().await;

        false
    };

    select!(stop_fut, sleep_fut).await
}
