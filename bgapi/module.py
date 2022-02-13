from __future__ import absolute_import

import logging
import sys
import time
import struct
import operator

from functools import wraps
from contextlib import contextmanager
from collections import defaultdict, namedtuple, deque
from threading import Event, Lock

from .api import BlueGigaAPI, BlueGigaCallbacks
from .cmd_def import gap_discoverable_mode, gap_connectable_mode, gap_discover_mode, \
    connection_status_mask, sm_io_capability, RESULT_CODE

logger = logging.getLogger(__name__)

GET_ADDRESS = "Read Address in Progress"
PROCEDURE = "Procedure in Progress"
START_ENCRYPTION = "Start Encryption in Progress"
READ_ATTRIBUTE = "Attribute Read in Progress"
WRITE_ATTRIBUTE = "Attribute Write in Progress"
SEND_ATTRIBUTE = "Attribute Send in Progress"
CONNECT = "Connection Attempt in Progress"
DISCONNECT = "Disconnect in Progress"
CONN_PARAM_UPDATE = "Connection Parameter Update Expected"

BLE_GAP_AD_TYPE_STRINGS = {
    0x01: "BLE_GAP_AD_TYPE_FLAGS",
    0x02: "BLE_GAP_AD_TYPE_16BIT_SERVICE_UUID_MORE_AVAILABLE",
    0x03: "BLE_GAP_AD_TYPE_16BIT_SERVICE_UUID_COMPLETE",
    0x04: "BLE_GAP_AD_TYPE_32BIT_SERVICE_UUID_MORE_AVAILABLE",
    0x05: "BLE_GAP_AD_TYPE_32BIT_SERVICE_UUID_COMPLETE",
    0x06: "BLE_GAP_AD_TYPE_128BIT_SERVICE_UUID_MORE_AVAILABLE",
    0x07: "BLE_GAP_AD_TYPE_128BIT_SERVICE_UUID_COMPLETE",
    0x08: "BLE_GAP_AD_TYPE_SHORT_LOCAL_NAME",
    0x09: "BLE_GAP_AD_TYPE_COMPLETE_LOCAL_NAME",
    0x0A: "BLE_GAP_AD_TYPE_TX_POWER_LEVEL",
    0x0D: "BLE_GAP_AD_TYPE_CLASS_OF_DEVICE",
    0x0E: "BLE_GAP_AD_TYPE_SIMPLE_PAIRING_HASH_C",
    0x0F: "BLE_GAP_AD_TYPE_SIMPLE_PAIRING_RANDOMIZER_R",
    0x10: "BLE_GAP_AD_TYPE_SECURITY_MANAGER_TK_VALUE",
    0x11: "BLE_GAP_AD_TYPE_SECURITY_MANAGER_OOB_FLAGS",
    0x12: "BLE_GAP_AD_TYPE_SLAVE_CONNECTION_INTERVAL_RANGE",
    0x14: "BLE_GAP_AD_TYPE_SOLICITED_SERVICE_UUIDS_16BIT",
    0x15: "BLE_GAP_AD_TYPE_SOLICITED_SERVICE_UUIDS_128BIT",
    0x16: "BLE_GAP_AD_TYPE_SERVICE_DATA",
    0x17: "BLE_GAP_AD_TYPE_PUBLIC_TARGET_ADDRESS",
    0x18: "BLE_GAP_AD_TYPE_RANDOM_TARGET_ADDRESS",
    0x19: "BLE_GAP_AD_TYPE_APPEARANCE",
    0x1A: "BLE_GAP_AD_TYPE_ADVERTISING_INTERVAL",
    0x1B: "BLE_GAP_AD_TYPE_LE_BLUETOOTH_DEVICE_ADDRESS",
    0x1C: "BLE_GAP_AD_TYPE_LE_ROLE",
    0x1D: "BLE_GAP_AD_TYPE_SIMPLE_PAIRING_HASH_C256",
    0x1E: "BLE_GAP_AD_TYPE_SIMPLE_PAIRING_RANDOMIZER_R256",
    0X1F: "BLE_GAP_AD_TYPE_LIST_SERVICE_SOLICITATION_32BIT_UUID",
    0x20: "BLE_GAP_AD_TYPE_SERVICE_DATA_32BIT_UUID",
    0x21: "BLE_GAP_AD_TYPE_SERVICE_DATA_128BIT_UUID",
    0X22: "BLE_GAP_AD_TYPE_LE_SECURE_CONNECTIONS_CONFIRMATION_VALUE",
    0X23: "BLE_GAP_AD_TYPE_LE_SECURE_CONNECTIONS_RANDOM_VALUE",
    0X24: "BLE_GAP_AD_TYPE_URI",
    0X25: "BLE_GAP_AD_TYPE_INDOOR_POSITIONING",
    0X26: "BLE_GAP_AD_TYPE_TRANSPORT_DISCOVERY_DATA",
    0X27: "BLE_GAP_AD_TYPE_LE_SUPPORTED_FEATURES",
    0X28: "BLE_GAP_AD_TYPE_CHANNEL_MAP_UPDATE_INDICATION",
    0X29: "BLE_GAP_AD_TYPE_PB_ADV",
    0x2A: "BLE_GAP_AD_TYPE_MESH_MESSAGE",
    0x2B: "BLE_GAP_AD_TYPE_MESH_BEACON",
    0x3D: "BLE_GAP_AD_TYPE_3D_INFORMATION_DATA",
    0xFF: "BLE_GAP_AD_TYPE_MANUFACTURER_SPECIFIC_DATA"
}

BLE_GAP_AD_TYPE = {v: k for k, v in BLE_GAP_AD_TYPE_STRINGS.items()}

class BlueGigaModuleException(Exception):
    pass

class Timeout(BlueGigaModuleException):
    """Procedure type module timeout."""

class RemoteError(BlueGigaModuleException):

    def __init__(self, resultCode):
        self.code = resultCode
        self.text = RESULT_CODE.get(self.code, "UNKNOWN")

        super(RemoteError, self).__init__("0x%04X: %s" % (self.code, self.text))

class Disconnected(BlueGigaModuleException):

    def __init__(self, resultCode, extraMsg=""):
        self.code = resultCode
        self.text = RESULT_CODE.get(self.code, "UNKNOWN")
        self.extraMsg = extraMsg

        super(Disconnected, self).__init__("0x%04X: %s %s" % (self.code, self.text, self.extraMsg))

AdvancedSegment = namedtuple("AdvancedSegment", ["type_code", "type_name", "data"])

class BLEScanResponse(object):
    def __init__(self, rssi, packet_type, sender, address_type, bond, data):
        self.rssi = rssi
        self.packet_type = packet_type
        self.sender = sender
        self.address_type = address_type
        self.bond = bond
        self.data = data
        self.services = []
        self.adv_payload = []
        self.name = ''
        self.created = time.time()

    def get_sender_address(self):
        return self.sender

    def parse_advertisement_data(self):
        remaining = self.data
        while len(remaining) > 0:
            length, = struct.unpack('B', remaining[:1])
            gap_data = remaining[1:length+1]

            try:
                (adv_seg_type,) = struct.unpack('B', gap_data[:1])
                adv_seg_name = self.get_ad_type_string(adv_seg_type)
            except (KeyError, struct.error):
                adv_seg_name = None

            self.adv_payload.append(AdvancedSegment(adv_seg_type, adv_seg_name, gap_data[1:]))
            #print("GAP Data: %s" % ("".join(["\\x%02x" % ord(i) for i in gap_data])))
            remaining = remaining[length+1:]

            if adv_seg_type == 0x1:  # Flags
                pass
            elif adv_seg_type == 0x02 or adv_seg_type == 0x03:  # Incomplete/Complete list of 16-bit UUIDs
                for i in range(1, len(gap_data) - 1, 2):
                    self.services += [gap_data[i:i+2]]
            elif adv_seg_type == 0x04 or adv_seg_type == 0x05:  # Incomplete list of 32-bit UUIDs
                for i in range(1, len(gap_data) - 3, 4):
                    self.services += [gap_data[i:i+4]]
            elif adv_seg_type == 0x06 or adv_seg_type == 0x07:  # Incomplete list of 128-bit UUIDs
                for i in range(1, len(gap_data) - 15, 16):
                    self.services += [gap_data[i:i+16]]
            elif adv_seg_type == 0x09: # Device name
                self.name = gap_data[1:].decode('utf8')

    def get_services(self):
        self.parse_advertisement_data()
        return self.services

    def get_name(self):
        self.parse_advertisement_data()
        return self.name

    def get_ad_type_string(self, type_ord):
        return BLE_GAP_AD_TYPE_STRINGS[type_ord]


class GATTCharacteristicDescriptor(object):
    def __init__(self, handle, value):
        self.handle = handle
        self.value = value


class GATTService(object):
    PRIMARY_SERVICE_UUID = b"\x00\x28"  # [0x00, 0x28]
    SECONDARY_SERVICE_UUID = b"\x01\x28"  # [0x01, 0x28]

    def __init__(self, start_handle, end_handle, uuid):
        self.start_handle = start_handle
        self.end_handle = end_handle
        self.uuid = uuid


class GATTCharacteristic(object):
    CHARACTERISTIC_UUID = b"\x03\x28"
    CLIENT_CHARACTERISTIC_CONFIG = b"\x02\x29"
    USER_DESCRIPTION = b"\x01\x29"

    def __init__(self, handle, properties):
        self.handle = handle
        self.properties, self.value_handle = struct.unpack("<BH", properties[:3])
        self.uuid = properties[3:]
        self.descriptors = {}
        self.value = None

    def is_readable(self):
        return (self.properties & 0x02) > 0

    def is_write_no_response(self):
        return (self.properties & 0x04) > 0

    def is_writable(self):
        return (self.properties & 0x08) > 0

    def has_notify(self):
        return (self.properties & 0x10) > 0

    def has_indicate(self):
        return (self.properties & 0x20) > 0

    def has_reliable_write(self):
        return (self.properties & 0x80) > 0

    def add_descriptor(self, uuid, handle, value):
        if uuid == self.uuid:
            self.value = value
        else:
            self.descriptors[uuid] = GATTCharacteristicDescriptor(handle, value)

    def get_descriptor_by_uuid(self, uuid):
        if uuid not in self.descriptors:
            return None
        else:
            return self.descriptors[uuid]


class ProcedureCallHandle(object):

    __slots__ = ("event", "result")

    def __init__(self):
        self.event = Event()

    def setResult(self, result):
        self.result = result
        self.event.set()

class ProcedureManager(object):
    def __init__(self):
        self._typeLocks = defaultdict(Lock) # procedure type -> execution lock for that
        self._handles = {} # procedure type -> <ProcedureCallHandle>
        self.ioTimestamps = None

    def set_max_procedures(self, max_procedures):
        self.ioTimestamps = defaultdict(lambda: deque([0], maxlen=max_procedures)) # procedure type -> time.time() of the last I/Os to the device

    @contextmanager
    def procedure_call(self, procedure_type, timeout, throwError=True):
        if not self.ioTimestamps:
            self.set_max_procedures(6)
        with self._typeLocks[procedure_type]:
            assert procedure_type not in self._handles # Nobody else is waiting for this procedure type

            handle = ProcedureCallHandle()
            self._handles[procedure_type] = handle

            # Ensure that the lib does not exceed connection interval.
            earliest_interval_ts = self.ioTimestamps[procedure_type][0]
            interval = self.get_procedure_call_interval()
            wait_until = earliest_interval_ts + interval
            now = time.time()
            if now<wait_until:
                time.sleep(max(0.00125, wait_until - now))

            try:

                yield handle # allow the caller to execute his API call in this context.
                # the Result pair can be used by the context for
                self.ioTimestamps[procedure_type].append(time.time())


                if not handle.event.wait(timeout):
                    raise Timeout("Procedure call timed out")

                if throwError and handle.result != 0x0000:
                    raise RemoteError(handle.result)
            finally:
                del self._handles[procedure_type]

    def procedure_complete(self, procedure_type, result=0x0000):
        if self.ioTimestamps:
            self.ioTimestamps[procedure_type].append(time.time())
        try:
            handle = self._handles[procedure_type]
            handle.setResult(result)
        except KeyError:
            # This procedure had not been started, ignore the result
            pass

    def get_active_procedure_calls(self):
        return tuple(self._handles.keys())

    def get_procedure_call_interval(self):
        """Returns minimum time distance between two procedure calls (in seconds)."""
        return 0

def connected(fn):
    """This decorator checks that the BLEConnection is still connected before executing the payload function."""
    @wraps(fn)
    def _wrapper_(self, *args, **kwargs):
        if self._disconnected is not None:
            raise Disconnected(self._disconnected, "This connection is no longer connected")
        return fn(self, *args, **kwargs)

    return _wrapper_


class BLEConnection(ProcedureManager):
    def __init__(self, api, handle, address, address_type, interval, timeout, latency, bonding):
        super(BLEConnection, self).__init__()
        self._api = api
        self.handle = handle
        self.address = address
        self.address_type = address_type
        self.interval = interval
        self.timeout = timeout
        self.latency = latency
        self.bond_handle = bonding
        self.services = {}
        self.characteristics = {}
        self.handle_uuid = {}
        self.uuid_handle = {}
        self.handle_value = {}
        self.attrclient_value_cb = {}
        self._disconnected = None
        self._min_connection_interval = 0

    def is_connected(self):
        return self._disconnected is None

    def set_disconnect(self, reason):
        self._disconnected = reason

    def set_disconnected(self, reason):
        self.set_disconnect(reason)
        # Notify any pending procedure calls
        for typ in self.get_active_procedure_calls():
            self.procedure_complete(typ, reason)

    def get_conn_interval_ms(self):
        return self.interval * 1.25

    def set_min_connection_interval(self, interval):
        self._min_connection_interval = 0 * float(interval)

    def get_procedure_call_interval(self):
        # Overrides `ProcedureManager`.get_procedure_call_interval
        return max(
            self._min_connection_interval,
            self.get_conn_interval_ms() / 1000.0,
        )

    def get_timeout_ms(self):
        return self.timeout * 10

    def assign_attrclient_value_callback(self, handle, callback):
        self.attrclient_value_cb[handle] = callback

    def get_connected_address(self):
        return self.address

    def update_service(self, start_handle, end_handle, uuid):
        self.services[start_handle] = GATTService(start_handle, end_handle, uuid)

    def get_services(self):
        return [j for i, j in sorted(self.services.items(), key=operator.itemgetter(0))]

    def get_characteristics(self):
        return [j for i, j in sorted(self.characteristics.items(), key=operator.itemgetter(0))]

    def update_uuid(self, handle, uuid):
        self.handle_uuid[handle] = uuid
        if uuid in self.uuid_handle:
            self.uuid_handle[uuid] += [handle]
        else:
            self.uuid_handle[uuid] = [handle]

    def get_handles_by_uuid(self, uuid):
        if uuid in self.uuid_handle:
            return self.uuid_handle[uuid]

    def get_uuid_by_handle(self, handle):
        if handle in self.handle_uuid:
            return self.handle_uuid[handle]

    def update_handle(self, handle, value):
        if handle in self.handle_uuid:
            if self.handle_uuid[handle] == GATTCharacteristic.CHARACTERISTIC_UUID:
                self.characteristics[handle] = GATTCharacteristic(handle, value)
            else:
                for characteristic in self.get_characteristics()[::-1]:
                    if characteristic.handle < handle:
                        characteristic.add_descriptor(self.handle_uuid[handle], handle, value)
                        break
        else:
            raise BlueGigaModuleException("Attribute Value for Handle %d received with unknown UUID!" % (handle, ))
        if handle in self.attrclient_value_cb:
            try:
                self.attrclient_value_cb[handle](value)
            except Exception:
                logger.exception("Callback exception")

    @connected
    def read_by_group_type(self, group_type, timeout=3):
        with self.procedure_call(PROCEDURE, timeout):
            self._api.ble_cmd_attclient_read_by_group_type(self.handle, 1, 65535, group_type)

    @connected
    def read_by_type(self, service, type, timeout=3):
        with self.procedure_call(PROCEDURE, timeout):
            self._api.ble_cmd_attclient_read_by_type(self.handle, service.start_handle, service.end_handle, type)

    @connected
    def read_all_characteristics_by_type(self, type, timeout=3):
        with self.procedure_call(PROCEDURE, timeout):
            self._api.ble_cmd_attclient_read_by_type(self.handle, 0x0001, 0xFFFF, type)

    @connected
    def find_information(self, service, timeout=5):
        with self.procedure_call(PROCEDURE, timeout):
            self._api.ble_cmd_attclient_find_information(self.handle, service.start_handle, service.end_handle)

    @connected
    def find_all_information(self, timeout=5):
        with self.procedure_call(PROCEDURE, timeout):
            self._api.ble_cmd_attclient_find_information(self.handle, 0x0001, 0xFFFF)

    @connected
    def read_by_handle(self, handle, timeout=3):
        with self.procedure_call(READ_ATTRIBUTE, timeout):
            self._api.ble_cmd_attclient_read_by_handle(self.handle, handle)

    def write_by_uuid(self, uuid, value, timeout=3):
        for handle in self.uuid_handle[uuid]:
            self.write_by_handle(handle, value, timeout)

    @connected
    def write_by_handle(self, handle, value, timeout=3):
        with self.procedure_call(WRITE_ATTRIBUTE, timeout):
            self._api.ble_cmd_attclient_attribute_write(self.handle, handle, value)

    def wr_noresp_by_uuid(self, uuid, value, timeout=3):
        for handle in self.uuid_handle[uuid]:
            self.wr_noresp_by_handle(handle, value, timeout)

    @connected
    def wr_noresp_by_handle(self, handle, value, timeout=3, attempts=1):
        for i in range(attempts):

            with self.procedure_call(PROCEDURE, timeout, throwError=False) as procedure_handle:
                self._api.ble_cmd_attclient_write_command(self.handle, handle, value)

            if procedure_handle.result != 0x0000:
                time.sleep(self.interval * 0.00125)  # Sleep for a connection interval
            else:
                break

    def read_long_by_uuid(self, uuid, timeout=3):
        for handle in self.uuid_handle[uuid]:
            self.read_long_by_handle(self.uuid_handle[uuid], timeout)

    @connected
    def read_long_by_handle(self, handle, timeout=3):
        with self.procedure_call(PROCEDURE, timeout):
            self._api.ble_cmd_attclient_read_long(self.handle, handle)

    def reliable_write_by_uuid(self, uuid, value, offset=0, timeout=3):
        for handle in self.uuid_handle[uuid]:
            self.reliable_write_by_handle(handle, value, offset, timeout)

    @connected
    def reliable_write_by_handle(self, handle, value, offset=0, timeout=3):
        for i in range((len(value) // 18)+1):
            chunk = value[18*i+offset:min(18*(i+1)+offset, len(value))]
            with self.procedure_call(PROCEDURE, timeout):
                self._api.ble_cmd_attclient_prepare_write(self.handle, handle, 18*i+offset, chunk)

        with self.procedure_call(PROCEDURE, timeout):
            self._api.ble_cmd_attclient_execute_write(self.handle, 1) # 1 = commit, 0 = cancel

    def characteristic_subscription(self, characteristic, indicate=True, notify=True, timeout=1):
        descriptor = characteristic.get_descriptor_by_uuid(GATTCharacteristic.CLIENT_CHARACTERISTIC_CONFIG)
        if not descriptor:
            raise BlueGigaModuleException("Unable to find Client Characteristic Config (must Read by Type 0x2902)")
        config = struct.pack('BB', (2 if indicate else 0) + (1 if notify else 0), 0)
        with self.procedure_call(PROCEDURE, timeout):
            self.write_by_handle(descriptor.handle, config, timeout=timeout)

    @connected
    def request_encryption(self, bond=True, timeout=1):
        with self.procedure_call(START_ENCRYPTION, timeout):
            self._api.ble_cmd_sm_encrypt_start(self.handle, 1 if bond else 0)

class BlueGigaModule(BlueGigaCallbacks, ProcedureManager):
    CONNECTION_OBJECT = BLEConnection

    def __init__(self, port, baud=115200, timeout=0.1):
        super(BlueGigaModule, self).__init__()
        self._api = BlueGigaAPI(port, callbacks=self, baud=baud, timeout=timeout)
        self.address = None
        self._module_info = None
        self.scan_responses = None
        self.connections = {}
        self._api.start_daemon()
        self.procedure_in_progress = False

    def pipe_logs_to_terminal(self, level=logging.INFO):
        term = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter(self._api._serial.portstr + ': %(asctime)s - %(name)s - %(levelname)s - %(message)s')
        term.setFormatter(formatter)
        api_logger = logging.getLogger("bgapi")
        api_logger.addHandler(term)
        api_logger.setLevel(level=level)

    def shutdown(self):
        self._api.stop_daemon()

    def get_module_info(self, timeout=0.5):
        start = time.time()
        if not self._module_info:
            self._api.ble_cmd_system_get_info()
        while not self._module_info and time.time() < start + timeout:
            pass
        return self._module_info

    def get_ble_address(self, timeout=1):
        with self.procedure_call(GET_ADDRESS, timeout) as handle:
            self._api.ble_cmd_system_address_get()
        return self.address

    def reset_ble_state(self):
        """ Disconnect, End Procedure, and Disable Advertising """
        self._api.ble_cmd_gap_set_mode(gap_discoverable_mode['gap_non_discoverable'],
                                       gap_connectable_mode['gap_non_connectable'])

        toDisconnect = set(self.connections.keys())
        toDisconnect.update(range(8))
        for i in toDisconnect:
            try:
                self.disconnect(i)
            except RemoteError:
                pass
        self._api.ble_cmd_gap_end_procedure()

    def disconnect(self, connection):
        try:
            with self.procedure_call(DISCONNECT, timeout=None):
                try:
                    self._api.ble_cmd_connection_disconnect(connection=connection.handle)
                except AttributeError:
                    self._api.ble_cmd_connection_disconnect(connection=connection)
        except RemoteError as err:
            if err.code == 0x0186:
                # Not connected
                pass
            else:
                raise

    def allow_bonding(self):
        self._api.ble_cmd_sm_set_bondable_mode(1)

    def disallow_bonding(self):
        self._api.ble_cmd_sm_set_bondable_mode(0)

    def delete_bonding(self, handle=0):
        self._api.ble_cmd_sm_delete_bonding(handle)

    def set_device_capabilities(self, mitm=True, keysize=16, io=sm_io_capability['sm_io_capability_noinputnooutput']):
        self._api.ble_cmd_sm_set_parameters(mitm=1 if mitm else 0, min_key_size=keysize, io_capabilities=io)

    def set_out_of_band_data(self, oob):
        self._api.ble_cmd_sm_set_oob_data(oob.decode("hex"))

            
    def scan_all(self, timeout=20):
        return self._scan(mode=gap_discover_mode['gap_discover_observation'], timeout=timeout)
    
    def _scan(self, mode, timeout):
        self.scan_responses = None
        now = start = time.time()
        self._api.ble_cmd_gap_discover(mode=mode)
        while now < start + timeout:
            time.sleep(timeout - (now - start))
            now = time.time()
        self._api.ble_cmd_gap_end_procedure()
        return self.scan_responses

#------------- Response and Event Callbacks  -------------#

    def ble_rsp_system_address_get(self, address):
        super(BlueGigaModule, self).ble_rsp_system_address_get(address)
        self.address = address
        self.procedure_complete(GET_ADDRESS)

    def ble_evt_connection_status(self, connection, flags, address, address_type, conn_interval, timeout, latency, bonding):
        super(BlueGigaModule, self).ble_evt_connection_status(connection, flags, address, address_type, conn_interval, timeout, latency, bonding)
        if flags & connection_status_mask['connection_completed']:
            conn = self.CONNECTION_OBJECT(api=self._api, handle=connection, address=address,
                                          address_type=address_type, interval=conn_interval, timeout=timeout,
                                          latency=latency, bonding=bonding)
            self.connections[connection] = conn
            self.most_recent_connection = conn
            self.procedure_complete(CONNECT)
        if flags & connection_status_mask['connection_parameters_change']:
            self.connections[connection].flags = flags
            self.connections[connection].interval = conn_interval
            self.connections[connection].timeout = timeout
            self.connections[connection].latency = latency
            self.connections[connection].procedure_complete(CONN_PARAM_UPDATE)
        if flags & connection_status_mask['connection_encrypted']:
            self.connections[connection].flags = flags
            self.connections[connection].procedure_complete(START_ENCRYPTION)

    def ble_rsp_system_get_info(self, major, minor, patch, build, ll_version, protocol_version, hw):
        super(BlueGigaModule, self).ble_rsp_system_get_info(major, minor, patch, build, ll_version, protocol_version, hw)
        self._module_info = {"FW Version": "%d.%d.%d.%d" % (major, minor, patch, build),
                             "Link Layer Version": "%d" % ll_version,
                             "Protocol Version": "%d" % protocol_version,
                             "Hardware Version": "%d" % hw}

    def ble_rsp_connection_disconnect(self, connection, result):
        super(BlueGigaModule, self).ble_rsp_connection_disconnect(connection, result)
        if connection in self.connections:
            self.connections[connection].set_disconnect(result)
        self.procedure_complete(DISCONNECT, result=result)

    def ble_evt_connection_disconnected(self, connection, reason):
        super(BlueGigaModule, self).ble_evt_connection_disconnected(connection, reason)
        if connection in self.connections:
            self.connections[connection].set_disconnected(reason)
        self.procedure_complete(DISCONNECT, result=reason)

    def ble_rsp_gap_connect_direct(self, result, connection_handle):
        super(BlueGigaModule, self).ble_rsp_gap_connect_direct(result, connection_handle)
        if result and connection_handle in self.connections:
            self.connections[connection_handle].set_disconnected(result)
            self.procedure_complete(CONNECT, result=result)

    def ble_evt_gap_scan_response(self, rssi, packet_type, sender, address_type, bond, data):
        super(BlueGigaModule, self).ble_evt_gap_scan_response(rssi, packet_type, sender, address_type, bond, data)
        if not self.scan_responses:
            self.scan_responses = []
        self.scan_responses += [ BLEScanResponse(rssi, packet_type, sender, address_type, bond, data)]

class BlueGigaClient(BlueGigaModule):
    def connect_by_adv_data(self, adv_data, scan_timeout=3, conn_interval_min=0x20, conn_interval_max=0x30, connection_timeout=100, latency=0):
        responses = self.scan_all(timeout=scan_timeout)
        for resp in responses:
            if adv_data in resp.data:
                return self.connect(resp, scan_timeout, conn_interval_min, conn_interval_max, connection_timeout, latency)
        else:
            raise BlueGigaModuleException("%s not found in BLE scan!" % (adv_data))

    def scan_limited(self, timeout=20):
        return self._scan(mode=gap_discover_mode['gap_discover_limited'], timeout=timeout)

    def scan_general(self, timeout=20):
        return self._scan(mode=gap_discover_mode['gap_discover_generic'], timeout=timeout)

    def active_scan(self, scan_interval = 0x4B, scan_window = 0x32):
        return self._api.ble_cmd_gap_set_scan_parameters(scan_interval, scan_window, 1)

    def disable_scan(self, scan_interval = 0x4B, scan_window = 0x32):
        return self._api.ble_cmd_gap_set_scan_parameters(scan_interval, scan_window, 0)

    def connect(self, target, timeout=5, conn_interval_min=0x20, conn_interval_max=0x30, connection_timeout=100, latency=0):
        with self.procedure_call(CONNECT, timeout):
            self._api.ble_cmd_gap_connect_direct(
                address=target.sender,
                addr_type=target.address_type,
                conn_interval_min=conn_interval_min,
                conn_interval_max=conn_interval_max,
                timeout=connection_timeout,
                latency=latency
            )
        return self.most_recent_connection

    def ble_rsp_attclient_write_command(self, connection, result):
        super(BlueGigaClient, self).ble_rsp_attclient_write_command(connection=connection, result=result)
        self.procedure_complete(PROCEDURE, result=result)
        self.connections[connection].procedure_complete(PROCEDURE, result=result)

    #----------------  Events triggered by incoming data ------------------#

    def ble_evt_gap_scan_response(self, rssi, packet_type, sender, address_type, bond, data):
        super(BlueGigaClient, self).ble_evt_gap_scan_response(rssi, packet_type, sender, address_type, bond, data)
        if not self.scan_responses:
            self.scan_responses = []
        self.scan_responses += [ BLEScanResponse(rssi, packet_type, sender, address_type, bond, data) ]

    def ble_evt_attclient_find_information_found(self, connection, chrhandle, uuid):
        super(BlueGigaClient, self).ble_evt_attclient_find_information_found(connection, chrhandle, uuid)
        self.connections[connection].update_uuid(chrhandle, uuid)

    def ble_evt_attclient_attribute_value(self, connection, atthandle, type, value):
        super(BlueGigaClient, self).ble_evt_attclient_attribute_value(connection, atthandle, type, value)
        if connection in self.connections:
            self.connections[connection].update_handle(atthandle, value)
            self.connections[connection].procedure_complete(READ_ATTRIBUTE, type)

    def ble_evt_attclient_group_found(self, connection, start, end, uuid):
        super(BlueGigaClient, self).ble_evt_attclient_group_found(connection, start, end, uuid)
        self.connections[connection].update_service(start, end, uuid)

    def ble_evt_attclient_procedure_completed(self, connection, result, chrhandle):
        super(BlueGigaClient, self).ble_evt_attclient_procedure_completed(connection, result, chrhandle)
        self.procedure_complete(PROCEDURE, result=result)
        self.connections[connection].procedure_complete(PROCEDURE, result=result)
        self.connections[connection].procedure_complete(READ_ATTRIBUTE, result=result) # When the attribute read fails

    def ble_rsp_attclient_attribute_write(self, connection, result):
        super(BlueGigaClient, self).ble_rsp_attclient_attribute_write(connection, result)
        self.procedure_complete(PROCEDURE, result=result)
        self.connections[connection].procedure_complete(WRITE_ATTRIBUTE, result=result)

class BlueGigaServer(BlueGigaModule):
    def __init__(self, port, baud=115200, timeout=0.1):
        super(BlueGigaServer, self).__init__(port, baud, timeout)
        self.handle_types = {}
        self.handle_values = {}

    def start_advertisement(self, adv_mode, conn_mode, interval_min=1000, interval_max=1500, channels=0x07):
        self._api.ble_cmd_gap_set_adv_parameters(interval_min, interval_max, channels)
        self._api.ble_cmd_gap_set_mode(discover=adv_mode, connect=conn_mode)

    def advertise_general(self, interval_min=500, interval_max=1000, channels=0x7):
        self.start_advertisement(adv_mode=gap_discoverable_mode['gap_general_discoverable'],
                         conn_mode=gap_connectable_mode['gap_undirected_connectable'],
                         interval_min=interval_min,
                         interval_max=interval_max,
                         channels=channels)

    def get_ad_type_ord_by_string(self, adv_type):
        return BLE_GAP_AD_TYPE[adv_type]

    def setup_adv_data(self, adv_data):
        """
        Set advertising data for general advertising. Make sure to include
        at least advertising flags (BLE_GAP_AD_TYPE_FLAGS) to be a compliant
        BLE GATT server and for the BGAPI device to be detected.

        :param adv_data: Hex string of advertising data
        """
        self._api.ble_cmd_gap_set_adv_data(0, adv_data=adv_data.decode("hex"))

    def setup_adv_rsp_data(self, adv_rsp_data):
        """
        Set advertising data response. Requires adv_mode=gap_discoverable_mode['gap_user_data']
        in the start_advertisement() call for the data to be read-back by the Central.

        :param adv_rsp_data: Hex string of advertising response data
        """
        self._api.ble_cmd_gap_set_adv_data(1, adv_data=adv_rsp_data.decode("hex"))

    def setup_ibeacon(self, uuid, major, minor):
        advertisement_data = "020106"       # General discovery, Single Mode Device
        advertisement_data += "1AFF"        # Manufacturer Data
        advertisement_data += "4C000215"    # Preamble
        advertisement_data += uuid.replace('-',"")
        advertisement_data += "%04x%04x" % (major, minor)
        advertisement_data += "DC"          # Measured RSSI at 1m
        advertisement_data = advertisement_data.decode("hex") # LE byte list
        self.setup_adv_data(adv_data=advertisement_data)

    def setup_physical_web(self, uri):
        encodings = [("http://www.", "\x00"),
                     ("https://www.", "\x01"),
                     ("http://", "\x02"),
                     ("https://", "\x03"),
                     (".com/", '\x00'),
                     (".org/", '\x01'),
                     (".edu/", '\x02'),
                     (".net/", '\x03'),
                     (".info/", '\x04'),
                     (".biz/", '\x05'),
                     (".gov/", '\x06'),
                     (".com", '\x07'),
                     (".org", '\x08'),
                     (".edu", '\x09'),
                     (".net", '\x0A'),
                     (".info", '\x0B'),
                     (".biz", '\x0C'),
                     (".gov", '\x0D'),]
        encoded_uri = uri
        for enc in encodings:
            encoded_uri = encoded_uri.replace(enc[0], enc[1])
        if encoded_uri == uri:
            if not uri.startswith("urn-"):
                raise BlueGigaModuleException("Unable to encode URI:%s" % uri)
            else:
                encoded_uri = uri.replace("urn-", '04')
                encoded_uri = encoded_uri.replace('-', '')
                encoded_uri = encoded_uri.decode("hex")

        #advertisement_data = b"\x02\x01\x06"
        advertisement_data = b"\x03\x03\xD8\xFE"
        advertisement_data += struct.pack('B', 5+len(encoded_uri))
        advertisement_data += b"\x16\xD8\xFE\x00\x08"
        advertisement_data += encoded_uri
        self.setup_adv_data(adv_data=advertisement_data)

    def stop_advertising(self):
        self._api.ble_cmd_gap_set_mode(discover=gap_discoverable_mode['gap_non_discoverable'],
                                       connect=gap_connectable_mode['gap_undirected_connectable'])

    def write_attribute(self, handle, value, offset=0, timeout=1):
        with self.procedure_call(PROCEDURE, timeout):
            self._api.ble_cmd_attributes_write(handle=handle, offset=offset, value=value)

    # connection == 0xFF means notify all connections that have registered
    def send_attribute(self, handle, value, connection=0xFF, timeout=1):
        with self.procedure_call(SEND_ATTRIBUTE, timeout):
            self._api.ble_cmd_attributes_send(connection=connection, handle=handle, value=value)

    def read_by_handle(self, handle, offset, timeout):
        with self.procedure_call(READ_ATTRIBUTE, timeout):
            self._api.ble_cmd_attributes_read(handle, offset)
        return self.handle_values[handle]

    def read_type(self, handle, timeout=1):
        with self.procedure_call(READ_ATTRIBUTE, timeout):
            self._api.ble_cmd_attributes_read_type(handle)
        return self.handle_types[handle]


    #-------------------- Events triggered by incoming data ------------- #
    def ble_evt_attributes_status(self, handle, flags):
        super(BlueGigaModule, self).ble_evt_attributes_status(handle, flags)

    def ble_rsp_attributes_write(self, result):
        super(BlueGigaServer, self).ble_rsp_attributes_write(result)
        self.procedure_complete(PROCEDURE)

    def ble_rsp_attributes_send(self, result):
        super(BlueGigaServer, self).ble_rsp_attributes_send(result)
        self.procedure_complete(SEND_ATTRIBUTE)

    def ble_evt_attributes_value(self, connection, reason, handle, offset, value):
        super(BlueGigaServer, self).ble_evt_attributes_value(connection, reason, handle, offset, value)
        self.update_attribute_cache(handle, offset, value)

    def ble_rsp_attributes_read_type(self, handle, result, value):
        super(BlueGigaServer, self).ble_rsp_attributes_read_type(handle, result, value)
        self.handle_types[handle] = value
        self.procedure_complete(READ_ATTRIBUTE)

    def ble_rsp_attributes_read(self, handle, offset, result, value):
        super(BlueGigaServer, self).ble_rsp_attributes_read(handle, offset, result, value)
        self.update_attribute_cache(handle, offset, value)
        self.procedure_complete(READ_ATTRIBUTE)

    def update_attribute_cache(self, handle, offset, value):
        if handle in self.handle_values and offset > 0:
            self.handle_values[handle] = self.handle_values[handle][:offset] + value
        elif offset > 0:
            self.handle_values[handle] = b"\x00"*offset + value
        else:
            self.handle_values[handle] = value
