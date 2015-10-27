import threading
import struct
import serial
import logging

from cmd_def import RESULT_CODE, ATTRIBUTE_CHANGE_REASON, ATTRIBUTE_STATUS_FLAGS, ATTRIBUTE_VALUE_TYPE

logger = logging.getLogger("bgapi")

MAX_BGAPI_PACKET_SIZE = 3 + 2048

class BlueGigaAPI(object):
    def __init__(self, port, callbacks=None, baud=115200, timeout=1):
        self._serial = serial.Serial(port=port, baudrate=baud, timeout=timeout)
        self._serial.flushInput()
        self._serial.flushOutput()
        self.rx_buffer = ""
        self._packet_size = 4
        self._timeout = timeout
        if not callbacks:
            self._callbacks = BlueGigaCallbacks()
        else:
            self._callbacks = callbacks

    def _run(self):
        self.rx_buffer = ""
        while (self._continue):
            self.poll_serial()
        self._serial.close()

    def poll_serial(self, max_read_len=MAX_BGAPI_PACKET_SIZE):
        self.rx_buffer += self._serial.read(min(self._packet_size - len(self.rx_buffer), max_read_len))
        while len(self.rx_buffer) >= self._packet_size:
            self._packet_size = 4 + (ord(self.rx_buffer[0]) & 0x07)*256 + ord(self.rx_buffer[1])
            if len(self.rx_buffer) < self._packet_size:
                break
            packet, self.rx_buffer = self.rx_buffer[:self._packet_size], self.rx_buffer[self._packet_size:]
            self._packet_size = 4
            self.parse_bgapi_packet(packet)

    def start_daemon(self):
        """
        Initiates a thread which manages all traffic received from serial
        and dispatches it to the appropriate callback
        """
        self._continue = True
        self.t = threading.Thread(target=self._run, args=())
        self.t.setDaemon(True)
        self.t.start()

    def stop_daemon(self):
        """
        Stops the thread which is monitoring the serial port for incoming
        traffic from the device.
        :return:
        """
        self._continue = False
        self.t.join(self._timeout)

    def daemon_running(self):
        return self._continue

    def send_command(self, packet_class, packet_command, payload=b''):
        """
        It is easier to use the ble_cmd methods, use this if you know how to compose your own BGAPI packets.
        """
        cmd = struct.pack('>HBB', len(payload), packet_class, packet_command) + payload
        logger.debug('=>[ ' + ' '.join(['%02X' % ord(b) for b in cmd ]) + ' ]')
        self._serial.write(cmd)

    def ble_cmd_system_reset(self, boot_in_dfu):
        self.send_command(0, 0, struct.pack('<B', boot_in_dfu))
    def ble_cmd_system_hello(self):
        self.send_command(0, 1)
    def ble_cmd_system_address_get(self):
        self.send_command(0, 2)
    def ble_cmd_system_reg_write(self, address, value):
        self.send_command(0, 3, struct.pack('<HB', address, value))
    def ble_cmd_system_reg_read(self, address):
        self.send_command(0, 4, struct.pack('<H', address))
    def ble_cmd_system_get_counters(self):
        self.send_command(0, 5)
    def ble_cmd_system_get_connections(self):
        self.send_command(0, 6)
    def ble_cmd_system_read_memory(self, address, length):
        self.send_command(0, 7, struct.pack('<IB', address, length))
    def ble_cmd_system_get_info(self):
        self.send_command(0, 8)
    def ble_cmd_system_endpoint_tx(self, endpoint, data):
        self.send_command(0, 9, struct.pack('<BB' + str(len(data)) + 's', endpoint, len(data), data))
    def ble_cmd_system_whitelist_append(self, address, address_type):
        self.send_command(0, 10, struct.pack('<6sB', address, address_type))
    def ble_cmd_system_whitelist_remove(self, address, address_type):
        self.send_command(0, 11, struct.pack('<6sB', address, address_type))
    def ble_cmd_system_whitelist_clear(self):
        self.send_command(0, 12)
    def ble_cmd_system_endpoint_rx(self, endpoint, size):
        self.send_command(0, 13, struct.pack('<BB', endpoint, size))
    def ble_cmd_system_endpoint_set_watermarks(self, endpoint, rx, tx):
        self.send_command(struct.pack('<BBB', 0, 14, endpoint, rx, tx))
    def ble_cmd_flash_ps_defrag(self):
        self.send_command(1, 0)
    def ble_cmd_flash_ps_dump(self):
        self.send_command(1, 1)
    def ble_cmd_flash_ps_erase_all(self):
        self.send_command(1, 2)
    def ble_cmd_flash_ps_save(self, key, value):
        self.send_command(1, 3, struct.pack('<HB' + str(len(value)) + 's', key, len(value), value))
    def ble_cmd_flash_ps_load(self, key):
        self.send_command(1, 4, struct.pack('<H', key))
    def ble_cmd_flash_ps_erase(self, key):
        self.send_command(1, 5, struct.pack('<H', key))
    def ble_cmd_flash_erase_page(self, page):
        self.send_command(1, 6, struct.pack('<B', page))
    def ble_cmd_flash_write_words(self, address, words):
        self.send_command(1, 7, struct.pack('<HB' + str(len(words)) + 's', address, len(words), words))
    def ble_cmd_attributes_write(self, handle, offset, value):
        self.send_command(2, 0, struct.pack('<HBB' + str(len(value)) + 's', handle, offset, len(value), value))
    def ble_cmd_attributes_read(self, handle, offset):
        self.send_command(2, 1, struct.pack('<HH', handle, offset))
    def ble_cmd_attributes_read_type(self, handle):
        self.send_command(2, 2, struct.pack('<H', handle))
    def ble_cmd_attributes_user_read_response(self, connection, att_error, value):
        self.send_command(2, 3, struct.pack('<BBB' + str(len(value)) + 's', connection, att_error, len(value), value))
    def ble_cmd_attributes_user_write_response(self, connection, att_error):
        self.send_command(2, 4, struct.pack('<BB', connection, att_error))
    def ble_cmd_connection_disconnect(self, connection):
        self.send_command(3, 0, struct.pack('<B', connection))
    def ble_cmd_connection_get_rssi(self, connection):
        self.send_command(3, 1, struct.pack('<B', connection))
    def ble_cmd_connection_update(self, connection, interval_min, interval_max, latency, timeout):
        self.send_command(3, 2, struct.pack('<BHHHH', connection, interval_min, interval_max, latency, timeout))
    def ble_cmd_connection_version_update(self, connection):
        self.send_command(3, 3, struct.pack('<B', connection))
    def ble_cmd_connection_channel_map_get(self, connection):
        self.send_command(3, 4, struct.pack('<B', connection))
    def ble_cmd_connection_channel_map_set(self, connection, map):
        self.send_command(3, 5, struct.pack('<BB' + str(len(map)) + 's', connection, len(map), map))
    def ble_cmd_connection_features_get(self, connection):
        self.send_command(3, 6, struct.pack('<B', connection))
    def ble_cmd_connection_get_status(self, connection):
        self.send_command(3, 7, struct.pack('<B', connection))
    def ble_cmd_connection_raw_tx(self, connection, data):
        self.send_command(3, 8, struct.pack('<BB' + str(len(data)) + 's', connection, len(data), data))
    def ble_cmd_attclient_find_by_type_value(self, connection, start, end, uuid, value):
        self.send_command(4, 0, struct.pack('<BHHHB' + str(len(value)) + 's', connection, start, end, uuid, len(value), value))
    def ble_cmd_attclient_read_by_group_type(self, connection, start, end, uuid): # =>[ 00 08 04 01 00 01 00 FF FF 02 00 28 ]
        self.send_command(4, 1, struct.pack('<BHHB' + str(len(uuid)) + 's', connection, start, end, len(uuid), uuid))
    def ble_cmd_attclient_read_by_type(self, connection, start, end, uuid):
        self.send_command(4, 2, struct.pack('<BHHB' + str(len(uuid)) + 's', connection, start, end, len(uuid), uuid))
    def ble_cmd_attclient_find_information(self, connection, start, end):
        self.send_command(4, 3, struct.pack('<BHH', connection, start, end))
    def ble_cmd_attclient_read_by_handle(self, connection, chrhandle):
        self.send_command(4, 4, struct.pack('<BH', connection, chrhandle))
    def ble_cmd_attclient_attribute_write(self, connection, atthandle, data):
        self.send_command(4, 5, struct.pack('<BHB' + str(len(data)) + 's', connection, atthandle, len(data), data))
    def ble_cmd_attclient_write_command(self, connection, atthandle, data):
        self.send_command(4, 6, struct.pack('<BHB' + str(len(data)) + 's', connection, atthandle, len(data), data))
    def ble_cmd_attclient_indicate_confirm(self, connection):
        self.send_command(4, 7, struct.pack('<B', connection))
    def ble_cmd_attclient_read_long(self, connection, chrhandle):
        self.send_command(4, 8, struct.pack('<BH', connection, chrhandle))
    def ble_cmd_attclient_prepare_write(self, connection, atthandle, offset, data):
        self.send_command(4, 9, struct.pack('<BHHB' + str(len(data)) + 's', connection, atthandle, offset, len(data), data))
    def ble_cmd_attclient_execute_write(self, connection, commit):
        self.send_command(4, 10, struct.pack('<BB', connection, commit))
    def ble_cmd_attclient_read_multiple(self, connection, handles):
        self.send_command(4, 11, struct.pack('<BB' + str(len(handles)) + 's', connection, len(handles), handles))
    def ble_cmd_sm_encrypt_start(self, handle, bonding):
        self.send_command(5, 0, struct.pack('<BB', handle, bonding))
    def ble_cmd_sm_set_bondable_mode(self, bondable):
        self.send_command(5, 1, struct.pack('<B', bondable))
    def ble_cmd_sm_delete_bonding(self, handle):
        self.send_command(5, 2, struct.pack('<B', handle))
    def ble_cmd_sm_set_parameters(self, mitm, min_key_size, io_capabilities):
        self.send_command(5, 3, struct.pack('<BBB', mitm, min_key_size, io_capabilities))
    def ble_cmd_sm_passkey_entry(self, handle, passkey):
        self.send_command(5, 4, struct.pack('<BI', handle, passkey))
    def ble_cmd_sm_get_bonds(self):
        self.send_command(5, 5)
    def ble_cmd_sm_set_oob_data(self, oob):
        self.send_command(5, 6, struct.pack('<B' + str(len(oob)) + 's', len(oob), oob))
    def ble_cmd_gap_set_privacy_flags(self, peripheral_privacy, central_privacy):
        self.send_command(6, 0, struct.pack('<BB', peripheral_privacy, central_privacy))
    def ble_cmd_gap_set_mode(self, discover, connect):
        self.send_command(6, 1, struct.pack('<BB', discover, connect))
    def ble_cmd_gap_discover(self, mode):
        self.send_command(6, 2, struct.pack('<B', mode))
    def ble_cmd_gap_connect_direct(self, address, addr_type, conn_interval_min, conn_interval_max, timeout, latency):
        self.send_command(6, 3, struct.pack('<6sBHHHH', address, addr_type, conn_interval_min, conn_interval_max, timeout, latency))
    def ble_cmd_gap_end_procedure(self):
        self.send_command(6, 4)
    def ble_cmd_gap_connect_selective(self, conn_interval_min, conn_interval_max, timeout, latency):
        self.send_command(6, 5, struct.pack('<HHHH', conn_interval_min, conn_interval_max, timeout, latency))
    def ble_cmd_gap_set_filtering(self, scan_policy, adv_policy, scan_duplicate_filtering):
        self.send_command(6, 6, struct.pack('<BBB', scan_policy, adv_policy, scan_duplicate_filtering))
    def ble_cmd_gap_set_scan_parameters(self, scan_interval, scan_window, active):
        self.send_command(6, 7, struct.pack('<HHB', scan_interval, scan_window, active))
    def ble_cmd_gap_set_adv_parameters(self, adv_interval_min, adv_interval_max, adv_channels):
        self.send_command(6, 8, struct.pack('<HHB', adv_interval_min, adv_interval_max, adv_channels))
    def ble_cmd_gap_set_adv_data(self, set_scanrsp, adv_data):
        self.send_command(6, 9, struct.pack('<BB' + str(len(adv_data)) + 's',  set_scanrsp, len(adv_data), adv_data))
    def ble_cmd_gap_set_directed_connectable_mode(self, address, addr_type):
        self.send_command(6, 10, struct.pack('<6sB', b''.join(chr(i) for i in address), addr_type))
    def ble_cmd_hardware_io_port_config_irq(self, port, enable_bits, falling_edge):
        self.send_command(7, 0, struct.pack('<BBB', port, enable_bits, falling_edge))
    def ble_cmd_hardware_set_soft_timer(self, time, handle, single_shot):
        self.send_command(7, 1, struct.pack('<IBB', time, handle, single_shot))
    def ble_cmd_hardware_adc_read(self, input, decimation, reference_selection):
        self.send_command(7, 2, struct.pack('<BBB', input, decimation, reference_selection))
    def ble_cmd_hardware_io_port_config_direction(self, port, direction):
        self.send_command(7, 3, struct.pack('<BB', port, direction))
    def ble_cmd_hardware_io_port_config_function(self, port, function):
        self.send_command(7, 4, struct.pack('<BB', port, function))
    def ble_cmd_hardware_io_port_config_pull(self, port, tristate_mask, pull_up):
        self.send_command(7, 5, struct.pack('<BBB', port, tristate_mask, pull_up))
    def ble_cmd_hardware_io_port_write(self, port, mask, data):
        self.send_command(7, 6, struct.pack('<BBB', port, mask, data))
    def ble_cmd_hardware_io_port_read(self, port, mask):
        self.send_command(7, 7, struct.pack('<BB', port, mask))
    def ble_cmd_hardware_spi_config(self, channel, polarity, phase, bit_order, baud_e, baud_m):
        self.send_command(7, 8, struct.pack('<BBBBBB', channel, polarity, phase, bit_order, baud_e, baud_m))
    def ble_cmd_hardware_spi_transfer(self, channel, data):
        self.send_command(7, 9, struct.pack('<BB' + str(len(data)) + 's', channel, len(data), data))
    def ble_cmd_hardware_i2c_read(self, address, stop, length):
        self.send_command(7, 10, struct.pack('<BBB', address, stop, length))
    def ble_cmd_hardware_i2c_write(self, address, stop, data):
        self.send_command(7, 11, struct.pack('<BBB' + str(len(data)) + 's', address, stop, len(data), data))
    def ble_cmd_hardware_set_txpower(self, power):
        self.send_command(7, 12, struct.pack('<B', power))
    def ble_cmd_hardware_timer_comparator(self, timer, channel, mode, comparator_value):
        self.send_command(7, 13, struct.pack('<BBBH', timer, channel, mode, comparator_value))
    def ble_cmd_test_phy_tx(self, channel, length, type):
        self.send_command(8, 0, struct.pack('<BBB', channel, length, type))
    def ble_cmd_test_phy_rx(self, channel):
        self.send_command(8, 1, struct.pack('<B', channel))
    def ble_cmd_test_phy_end(self):
        self.send_command(8, 2)
    def ble_cmd_test_phy_reset(self):
        self.send_command(8, 3)
    def ble_cmd_test_get_channel_map(self):
        self.send_command(8, 4)
    def ble_cmd_test_debug(self, input):
        self.send_command(8, 5, struct.pack('<B' + str(len(input)) + 's', len(input), input))

    def parse_bgapi_packet(self, packet, callbacks=None):
        logger.debug('<=[ ' + ' '.join(['%02X' % ord(b) for b in packet ]) + ' ]')
        message_type = ord(packet[0]) & 0x80
        technology_type = ord(packet[0]) & 0x78
        #payload_length = ord(packet[1])
        packet_class = ord(packet[2])
        packet_command = ord(packet[3])
        rx_payload = packet[4:]
        if technology_type:
            raise ValueError("Unsupported techlogy type: 0x%02x" % technology_type)
        if message_type == 0x00:
            # 0x00 = BLE response packet
            self.parse_bgapi_response(packet_class, packet_command, rx_payload, callbacks)
        elif message_type == 0x80:
            # 0x80 = BLE event packet
            self.parse_bgapi_event(packet_class, packet_command, rx_payload, callbacks)

    def parse_bgapi_response(self, packet_class, packet_command, rx_payload, callbacks=None):
        if callbacks is None:
            callbacks = self._callbacks
        if packet_class == 0:
            if packet_command == 0:
                callbacks.ble_rsp_system_reset()
            elif packet_command == 1:
                callbacks.ble_rsp_system_hello()
            elif packet_command == 2:
                callbacks.ble_rsp_system_address_get(address=rx_payload)
            elif packet_command == 3:
                result = struct.unpack('<H', rx_payload[:2])[0]
                callbacks.ble_rsp_system_reg_write(result=result)
            elif packet_command == 4:
                address, value = struct.unpack('<HB', rx_payload[:3])
                callbacks.ble_rsp_system_reg_read(address=address, value=value)
            elif packet_command == 5:
                txok, txretry, rxok, rxfail, mbuf = struct.unpack('<BBBBB', rx_payload[:5])
                callbacks.ble_rsp_system_get_counters(txok=txok, txretry=txretry, rxok=rxok, rxfail=rxfail, mbuf=mbuf)
            elif packet_command == 6:
                maxconn = struct.unpack('<B', rx_payload[:1])[0]
                callbacks.ble_rsp_system_get_connections(maxconn=maxconn)
            elif packet_command == 7:
                address, data_len = struct.unpack('<IB', rx_payload[:5])
                callbacks.ble_rsp_system_read_memory(address=address, data=rx_payload[5:])
            elif packet_command == 8:
                major, minor, patch, build, ll_version, protocol_version, hw = struct.unpack('<HHHHHBB', rx_payload[:12])
                callbacks.ble_rsp_system_get_info(major=major, minor=minor, patch=patch, build=build, ll_version=ll_version, protocol_version=protocol_version, hw=hw)
            elif packet_command == 9:
                result = struct.unpack('<H', rx_payload[:2])[0]
                callbacks.ble_rsp_system_endpoint_tx(result=result)
            elif packet_command == 10:
                result = struct.unpack('<H', rx_payload[:2])[0]
                callbacks.ble_rsp_system_whitelist_append(result=result)
            elif packet_command == 11:
                result = struct.unpack('<H', rx_payload[:2])[0]
                callbacks.ble_rsp_system_whitelist_remove(result=result)
            elif packet_command == 12:
                callbacks.ble_rsp_system_whitelist_clear()
            elif packet_command == 13:
                result, data_len = struct.unpack('<HB', rx_payload[:3])
                callbacks.ble_rsp_system_endpoint_rx(result=result, data=rx_payload[3:])
            elif packet_command == 14:
                result = struct.unpack('<H', rx_payload[:2])[0]
                callbacks.ble_rsp_system_endpoint_set_watermarks(result=result)
        elif packet_class == 1:
            if packet_command == 0:
                callbacks.ble_rsp_flash_ps_defrag()
            elif packet_command == 1:
                callbacks.ble_rsp_flash_ps_dump()
            elif packet_command == 2:
                callbacks.ble_rsp_flash_ps_erase_all()
            elif packet_command == 3:
                result = struct.unpack('<H', rx_payload[:2])[0]
                callbacks.ble_rsp_flash_ps_save(result=result)
            elif packet_command == 4:
                result, value_len = struct.unpack('<HB', rx_payload[:3])
                callbacks.ble_rsp_flash_ps_load(result=result, value=rx_payload[3:])
            elif packet_command == 5:
                callbacks.ble_rsp_flash_ps_erase()
            elif packet_command == 6:
                result = struct.unpack('<H', rx_payload[:2])[0]
                callbacks.ble_rsp_flash_erase_page(result=result)
            elif packet_command == 7:
                callbacks.ble_rsp_flash_write_words()
        elif packet_class == 2:
            if packet_command == 0:
                result = struct.unpack('<H', rx_payload[:2])[0]
                callbacks.ble_rsp_attributes_write(result=result)
            elif packet_command == 1:
                handle, offset, result, value_len = struct.unpack('<HHHB', rx_payload[:7])
                callbacks.ble_rsp_attributes_read(handle=handle, offset=offset, result=result, value=rx_payload[7:])
            elif packet_command == 2:
                handle, result, value_len = struct.unpack('<HHB', rx_payload[:5])
                callbacks.ble_rsp_attributes_read_type(handle=handle, result=result, value=rx_payload[5:])
            elif packet_command == 3:
                callbacks.ble_rsp_attributes_user_read_response()
            elif packet_command == 4:
                callbacks.ble_rsp_attributes_user_write_response()
        elif packet_class == 3:
            if packet_command == 0:
                connection, result = struct.unpack('<BH', rx_payload[:3])
                callbacks.ble_rsp_connection_disconnect(connection=connection, result=result)
            elif packet_command == 1:
                connection, rssi = struct.unpack('<Bb', rx_payload[:2])
                callbacks.ble_rsp_connection_get_rssi(connection=connection, rssi=rssi)
            elif packet_command == 2:
                connection, result = struct.unpack('<BH', rx_payload[:3])
                callbacks.ble_rsp_connection_update(connection=connection, result=result)
            elif packet_command == 3:
                connection, result = struct.unpack('<BH', rx_payload[:3])
                callbacks.ble_rsp_connection_version_update(connection=connection, result=result)
            elif packet_command == 4:
                connection, map_len = struct.unpack('<BB', rx_payload[:2])
                callbacks.ble_rsp_connection_channel_map_get(connection=connection, map=rx_payload[2:])
            elif packet_command == 5:
                connection, result = struct.unpack('<BH', rx_payload[:3])
                callbacks.ble_rsp_connection_channel_map_set(connection=connection, result=result)
            elif packet_command == 6:
                connection, result = struct.unpack('<BH', rx_payload[:3])
                callbacks.ble_rsp_connection_features_get(connection=connection, result=result)
            elif packet_command == 7:
                connection = struct.unpack('<B', rx_payload[:1])[0]
                callbacks.ble_rsp_connection_get_status(connection=connection)
            elif packet_command == 8:
                connection = struct.unpack('<B', rx_payload[:1])[0]
                callbacks.ble_rsp_connection_raw_tx(connection=connection)
        elif packet_class == 4:
            if packet_command == 0:
                connection, result = struct.unpack('<BH', rx_payload[:3])
                callbacks.ble_rsp_attclient_find_by_type_value(connection=connection, result=result)
            elif packet_command == 1:
                connection, result = struct.unpack('<BH', rx_payload[:3])
                callbacks.ble_rsp_attclient_read_by_group_type(connection=connection, result=result)
            elif packet_command == 2:
                connection, result = struct.unpack('<BH', rx_payload[:3])
                callbacks.ble_rsp_attclient_read_by_type(connection=connection, result=result)
            elif packet_command == 3:
                connection, result = struct.unpack('<BH', rx_payload[:3])
                callbacks.ble_rsp_attclient_find_information(connection=connection, result=result)
            elif packet_command == 4:
                connection, result = struct.unpack('<BH', rx_payload[:3])
                callbacks.ble_rsp_attclient_read_by_handle(connection=connection, result=result)
            elif packet_command == 5:
                connection, result = struct.unpack('<BH', rx_payload[:3])
                callbacks.ble_rsp_attclient_attribute_write(connection=connection, result=result)
            elif packet_command == 6:
                connection, result = struct.unpack('<BH', rx_payload[:3])
                callbacks.ble_rsp_attclient_write_command(connection=connection, result=result)
            elif packet_command == 7:
                result = struct.unpack('<H', rx_payload[:2])[0]
                callbacks.ble_rsp_attclient_indicate_confirm(result=result)
            elif packet_command == 8:
                connection, result = struct.unpack('<BH', rx_payload[:3])
                callbacks.ble_rsp_attclient_read_long(connection=connection, result=result)
            elif packet_command == 9:
                connection, result = struct.unpack('<BH', rx_payload[:3])
                callbacks.ble_rsp_attclient_prepare_write(connection=connection, result=result)
            elif packet_command == 10:
                connection, result = struct.unpack('<BH', rx_payload[:3])
                callbacks.ble_rsp_attclient_execute_write(connection=connection, result=result)
            elif packet_command == 11:
                connection, result = struct.unpack('<BH', rx_payload[:3])
                callbacks.ble_rsp_attclient_read_multiple(connection=connection, result=result)
        elif packet_class == 5:
            if packet_command == 0:
                handle, result = struct.unpack('<BH', rx_payload[:3])
                callbacks.ble_rsp_sm_encrypt_start(handle=handle, result=result)
            elif packet_command == 1:
                callbacks.ble_rsp_sm_set_bondable_mode()
            elif packet_command == 2:
                result = struct.unpack('<H', rx_payload[:2])[0]
                callbacks.ble_rsp_sm_delete_bonding(result=result)
            elif packet_command == 3:
                callbacks.ble_rsp_sm_set_parameters()
            elif packet_command == 4:
                result = struct.unpack('<H', rx_payload[:2])[0]
                callbacks.ble_rsp_sm_passkey_entry(result=result)
            elif packet_command == 5:
                bonds = struct.unpack('<B', rx_payload[:1])[0]
                callbacks.ble_rsp_sm_get_bonds(bonds=bonds)
            elif packet_command == 6:
                callbacks.ble_rsp_sm_set_oob_data()
        elif packet_class == 6:
            if packet_command == 0:
                callbacks.ble_rsp_gap_set_privacy_flags({  })
            elif packet_command == 1:
                result = struct.unpack('<H', rx_payload[:2])[0]
                callbacks.ble_rsp_gap_set_mode(result=result)
            elif packet_command == 2:
                result = struct.unpack('<H', rx_payload[:2])[0]
                callbacks.ble_rsp_gap_discover(result=result)
            elif packet_command == 3:
                result, connection_handle = struct.unpack('<HB', rx_payload[:3])
                callbacks.ble_rsp_gap_connect_direct(result=result, connection_handle=connection_handle)
            elif packet_command == 4:
                result = struct.unpack('<H', rx_payload[:2])[0]
                callbacks.ble_rsp_gap_end_procedure(result=result)
            elif packet_command == 5:
                result, connection_handle = struct.unpack('<HB', rx_payload[:3])
                callbacks.ble_rsp_gap_connect_selective(result=result, connection_handle=connection_handle)
            elif packet_command == 6:
                result = struct.unpack('<H', rx_payload[:2])[0]
                callbacks.ble_rsp_gap_set_filtering(result=result)
            elif packet_command == 7:
                result = struct.unpack('<H', rx_payload[:2])[0]
                callbacks.ble_rsp_gap_set_scan_parameters(result=result)
            elif packet_command == 8:
                result = struct.unpack('<H', rx_payload[:2])[0]
                callbacks.ble_rsp_gap_set_adv_parameters(result=result)
            elif packet_command == 9:
                result = struct.unpack('<H', rx_payload[:2])[0]
                callbacks.ble_rsp_gap_set_adv_data(result=result)
            elif packet_command == 10:
                result = struct.unpack('<H', rx_payload[:2])[0]
                callbacks.ble_rsp_gap_set_directed_connectable_mode(result=result)
        elif packet_class == 7:
            if packet_command == 0:
                result = struct.unpack('<H', rx_payload[:2])[0]
                callbacks.ble_rsp_hardware_io_port_config_irq(result=result)
            elif packet_command == 1:
                result = struct.unpack('<H', rx_payload[:2])[0]
                callbacks.ble_rsp_hardware_set_soft_timer(result=result)
            elif packet_command == 2:
                result = struct.unpack('<H', rx_payload[:2])[0]
                callbacks.ble_rsp_hardware_adc_read(result=result)
            elif packet_command == 3:
                result = struct.unpack('<H', rx_payload[:2])[0]
                callbacks.ble_rsp_hardware_io_port_config_direction(result=result)
            elif packet_command == 4:
                result = struct.unpack('<H', rx_payload[:2])[0]
                callbacks.ble_rsp_hardware_io_port_config_function(result=result)
            elif packet_command == 5:
                result = struct.unpack('<H', rx_payload[:2])[0]
                callbacks.ble_rsp_hardware_io_port_config_pull(result=result)
            elif packet_command == 6:
                result = struct.unpack('<H', rx_payload[:2])[0]
                callbacks.ble_rsp_hardware_io_port_write(result=result)
            elif packet_command == 7:
                result, port, data = struct.unpack('<HBB', rx_payload[:4])
                callbacks.ble_rsp_hardware_io_port_read(result=result, port=port, data=data)
            elif packet_command == 8:
                result = struct.unpack('<H', rx_payload[:2])[0]
                callbacks.ble_rsp_hardware_spi_config(result=result)
            elif packet_command == 9:
                result, channel, data_len = struct.unpack('<HBB', rx_payload[:4])
                callbacks.ble_rsp_hardware_spi_transfer(result=result, channel=channel, data=rx_payload[4:])
            elif packet_command == 10:
                result, data_len = struct.unpack('<HB', rx_payload[:3])
                callbacks.ble_rsp_hardware_i2c_read(result=result, data=rx_payload[3:])
            elif packet_command == 11:
                written = struct.unpack('<B', rx_payload[:1])[0]
                callbacks.ble_rsp_hardware_i2c_write(written=written)
            elif packet_command == 12:
                callbacks.ble_rsp_hardware_set_txpower()
            elif packet_command == 13:
                result = struct.unpack('<H', rx_payload[:2])[0]
                callbacks.ble_rsp_hardware_timer_comparator(result=result)
        elif packet_class == 8:
            if packet_command == 0:
                callbacks.ble_rsp_test_phy_tx()
            elif packet_command == 1:
                callbacks.ble_rsp_test_phy_rx()
            elif packet_command == 2:
                counter = struct.unpack('<H', rx_payload[:2])[0]
                callbacks.ble_rsp_test_phy_end(counter=counter)
            elif packet_command == 3:
                callbacks.ble_rsp_test_phy_reset()
            elif packet_command == 4:
                callbacks.ble_rsp_test_get_channel_map(channel_map=rx_payload[1:])
            elif packet_command == 5:
                callbacks.ble_rsp_test_debug(output=rx_payload[1:])

    def parse_bgapi_event(self, packet_class, packet_command, rx_payload, callbacks=None):
        if callbacks is None:
            callbacks = self._callbacks
        if packet_class == 0:
            if packet_command == 0:
                major, minor, patch, build, ll_version, protocol_version, hw = struct.unpack('<HHHHHBB', rx_payload[:12])
                callbacks.ble_evt_system_boot(major=major, minor=minor, patch=patch, build=build, ll_version=ll_version, protocol_version=protocol_version, hw=hw)
            elif packet_command == 1:
                callbacks.ble_evt_system_debug(data=rx_payload[1:])
            elif packet_command == 2:
                endpoint, data = struct.unpack('<BB', rx_payload[:2])
                callbacks.ble_evt_system_endpoint_watermark_rx(endpoint=endpoint, data=data)
            elif packet_command == 3:
                endpoint, data = struct.unpack('<BB', rx_payload[:2])
                callbacks.ble_evt_system_endpoint_watermark_tx(endpoint=endpoint, data=data)
            elif packet_command == 4:
                address, reason = struct.unpack('<HH', rx_payload[:4])
                callbacks.ble_evt_system_script_failure(address=address, reason=reason)
            elif packet_command == 5:
                callbacks.ble_evt_system_no_license_key({  })
        elif packet_class == 1:
            if packet_command == 0:
                key, value_len = struct.unpack('<HB', rx_payload[:3])
                callbacks.ble_evt_flash_ps_key(key=key, value=rx_payload[3:])
        elif packet_class == 2:
            if packet_command == 0:
                connection, reason, handle, offset, value_len = struct.unpack('<BBHHB', rx_payload[:7])
                callbacks.ble_evt_attributes_value(connection=connection, reason=reason, handle=handle, offset=offset, value=rx_payload[7:])
            elif packet_command == 1:
                connection, handle, offset, maxsize = struct.unpack('<BHHB', rx_payload[:6])
                callbacks.ble_evt_attributes_user_read_request(connection=connection, handle=handle, offset=offset, maxsize=maxsize)
            elif packet_command == 2:
                handle, flags = struct.unpack('<HB', rx_payload[:3])
                callbacks.ble_evt_attributes_status(handle=handle, flags=flags)
        elif packet_class == 3:
            if packet_command == 0:
                connection, flags, address, address_type, conn_interval, timeout, latency, bonding = struct.unpack('<BB6sBHHHB', rx_payload[:16])
                callbacks.ble_evt_connection_status(connection=connection, flags=flags, address=address, address_type=address_type, conn_interval=conn_interval, timeout=timeout, latency=latency, bonding=bonding)
            elif packet_command == 1:
                connection, vers_nr, comp_id, sub_vers_nr = struct.unpack('<BBHH', rx_payload[:6])
                callbacks.ble_evt_connection_version_ind(connection=connection, vers_nr=vers_nr, comp_id=comp_id, sub_vers_nr=sub_vers_nr)
            elif packet_command == 2:
                connection, features_len = struct.unpack('<BB', rx_payload[:2])
                features_data = [ord(b) for b in rx_payload[2:]]
                callbacks.ble_evt_connection_feature_ind(connection=connection, features=features_data)
            elif packet_command == 3:
                connection, data_len = struct.unpack('<BB', rx_payload[:2])
                callbacks.ble_evt_connection_raw_rx(connection=connection, data=rx_payload[2:])
            elif packet_command == 4:
                connection, reason = struct.unpack('<BH', rx_payload[:3])
                callbacks.ble_evt_connection_disconnected(connection=connection, reason=reason)
        elif packet_class == 4:
            if packet_command == 0:
                connection, attrhandle = struct.unpack('<BH', rx_payload[:3])
                callbacks.ble_evt_attclient_indicated(connection=connection, attrhandle=attrhandle)
            elif packet_command == 1:
                connection, result, chrhandle = struct.unpack('<BHH', rx_payload[:5])
                callbacks.ble_evt_attclient_procedure_completed(connection=connection, result=result, chrhandle=chrhandle)
            elif packet_command == 2:
                connection, start, end, uuid_len = struct.unpack('<BHHB', rx_payload[:6])
                callbacks.ble_evt_attclient_group_found(connection=connection, start=start, end=end, uuid=rx_payload[6:])
            elif packet_command == 3:
                connection, chrdecl, value, properties, uuid_len = struct.unpack('<BHHBB', rx_payload[:7])
                callbacks.ble_evt_attclient_attribute_found(connection=connection, chrdecl=chrdecl, value=value, properties=properties, uuid=rx_payload[7:])
            elif packet_command == 4:
                connection, chrhandle, uuid_len = struct.unpack('<BHB', rx_payload[:4])
                callbacks.ble_evt_attclient_find_information_found(connection=connection, chrhandle=chrhandle, uuid=rx_payload[4:])
            elif packet_command == 5:
                connection, atthandle, type, value_len = struct.unpack('<BHBB', rx_payload[:5])
                callbacks.ble_evt_attclient_attribute_value(connection=connection, atthandle=atthandle, type=type, value=rx_payload[5:])
            elif packet_command == 6:
                connection, handles_len = struct.unpack('<BB', rx_payload[:2])
                callbacks.ble_evt_attclient_read_multiple_response(connection=connection, handles=rx_payload[2:])
        elif packet_class == 5:
            if packet_command == 0:
                handle, packet, data_len = struct.unpack('<BBB', rx_payload[:3])
                callbacks.ble_evt_sm_smp_data(handle=handle, packet=packet, data=rx_payload[3:])
            elif packet_command == 1:
                handle, result = struct.unpack('<BH', rx_payload[:3])
                callbacks.ble_evt_sm_bonding_fail(handle=handle, result=result)
            elif packet_command == 2:
                handle, passkey = struct.unpack('<BI', rx_payload[:5])
                callbacks.ble_evt_sm_passkey_display(handle=handle, passkey=passkey)
            elif packet_command == 3:
                handle = struct.unpack('<B', rx_payload[:1])[0]
                callbacks.ble_evt_sm_passkey_request(handle=handle)
            elif packet_command == 4:
                bond, keysize, mitm, keys = struct.unpack('<BBBB', rx_payload[:4])
                callbacks.ble_evt_sm_bond_status(bond=bond, keysize=keysize, mitm=mitm, keys=keys)
        elif packet_class == 6:
            if packet_command == 0:
                rssi, packet_type, sender, address_type, bond, data_len = struct.unpack('<bB6sBBB', rx_payload[:11])
                callbacks.ble_evt_gap_scan_response(rssi=rssi, packet_type=packet_type, sender=sender,
                                                    address_type=address_type, bond=bond, data=rx_payload[11:] )
            elif packet_command == 1:
                discover, connect = struct.unpack('<BB', rx_payload[:2])
                callbacks.ble_evt_gap_mode_changed(discover=discover, connect=connect)
        elif packet_class == 7:
            if packet_command == 0:
                timestamp, port, irq, state = struct.unpack('<IBBB', rx_payload[:7])
                callbacks.ble_evt_hardware_io_port_status(timestamp=timestamp, port=port, irq=irq, state=state)
            elif packet_command == 1:
                handle = struct.unpack('<B', rx_payload[:1])[0]
                callbacks.ble_evt_hardware_soft_timer(handle=handle)
            elif packet_command == 2:
                input, value = struct.unpack('<Bh', rx_payload[:3])
                callbacks.ble_evt_hardware_adc_result(input=input, value=value)

class BlueGigaCallbacks(object):
    def ble_rsp_system_reset(self):
        logger.info("RSP-System Reset")

    def ble_rsp_system_hello(self):
        logger.info("RSP-System Hello")

    def ble_rsp_system_address_get(self, address):
        logger.info("RSP-System Address Get - " + "".join(["%02X" % ord(i) for i in address]))

    def ble_rsp_system_reg_write(self, result):
        logger.info("RSP-System Register Write: [%s]" % RESULT_CODE[result])

    def ble_rsp_system_reg_read(self, address, value):
        logger.info("RSP-System Register Read - Address:%02X - Value:%02X" % (address, value))

    def ble_rsp_system_get_counters(self, txok, txretry, rxok, rxfail, mbuf):
        logger.info("RSP-System Get Counters %d %d %d %d %d" % (txok, txretry, rxok, rxfail, mbuf))

    def ble_rsp_system_get_connections(self, maxconn):
        logger.info("RSP-System Get Connections - Maximum Connections:%d" % (maxconn))

    def ble_rsp_system_read_memory(self, address, data):
        logger.info("RSP-System Read Memory: %08x %s" % (address, data))

    def ble_rsp_system_get_info(self, major, minor, patch, build, ll_version, protocol_version, hw):
        logger.info("RSP-System Get Info: %d.%d.%d.%d, ll:%d, proto:%d, hw:%d" %
                    (major, minor, patch, build, ll_version, protocol_version, hw))

    def ble_rsp_system_endpoint_tx(self, result):
        logger.info("RSP-System Endpoint TX: [%s]" % RESULT_CODE[result])

    def ble_rsp_system_whitelist_append(self, result):
        logger.info("RSP-System Whitelist Append: [%s]" % RESULT_CODE[result])

    def ble_rsp_system_whitelist_remove(self, result):
        logger.info("RSP-System Whitelist Remove: [%s]" % RESULT_CODE[result])

    def ble_rsp_system_whitelist_clear(self):
        logger.info("RSP-System Whitelist Clear")

    def ble_rsp_system_endpoint_rx(self, result, data):
        logger.info("RSP-System Endpoint RX: [%s]" % (RESULT_CODE[result]))

    def ble_rsp_system_endpoint_set_watermarks(self, result):
        logger.info("RSP-System Endpoing Set Watermark: [%s]" %  RESULT_CODE[result])

    def ble_rsp_flash_ps_defrag(self):
        logger.info("RSP-Flash PS Defrag")

    def ble_rsp_flash_ps_dump(self):
        logger.info("RSP-Flash PS Dump")

    def ble_rsp_flash_ps_erase_all(self):
        logger.info("RSP-Flash PS Erase All")

    def ble_rsp_flash_ps_save(self, result):
        logger.info("RSP-Flash PS Save: [%s]" %  RESULT_CODE[result])

    def ble_rsp_flash_ps_load(self, result, value):
        logger.info("RSP-Flash PS Load: [%s]" %  (RESULT_CODE[result]))

    def ble_rsp_flash_ps_erase(self):
        logger.info("RSP-Flash PS Erase")

    def ble_rsp_flash_erase_page(self, result):
        logger.info("RSP-Flash Erase Page: [%s]" %  RESULT_CODE[result])

    def ble_rsp_flash_write_words(self):
        logger.info("RSP-Flash Write Words")

    def ble_rsp_attributes_write(self, result):
        logger.info("RSP-Attributes Write: [%s]" %  RESULT_CODE[result])

    def ble_rsp_attributes_read(self, handle, offset, result, value):
        logger.info("RSP-Attributes Read [%s] - Handle:%d - Offset:%d - Value:%s" %  (RESULT_CODE[result], handle, offset, "".join(["%02X" % ord(i) for i in value[::-1]])))

    def ble_rsp_attributes_read_type(self, handle, result, value):
        logger.info("RSP-Attributes Read Type [%s] - Handle:%d Value:%s" %  (RESULT_CODE[result], handle, "".join(["%02X" % ord(i) for i in value[::-1]])))

    def ble_rsp_attributes_user_read_response(self):
        logger.info("RSP-Attributes User Read Response")

    def ble_rsp_attributes_user_write_response(self):
        logger.info("RSP-Attributes User Write Response")

    def ble_rsp_connection_disconnect(self, connection, result):
        logger.info("RSP-Connection Disconnect - Connection:%d - [%s]" % (connection, RESULT_CODE[result]))

    def ble_rsp_connection_get_rssi(self, connection, rssi):
        logger.info("RSP-Connection Get RSSI: (%d, %d)" % (connection, rssi))

    def ble_rsp_connection_update(self, connection, result):
        logger.info("RSP-Connection Update: [%s] (%d)" % (RESULT_CODE[result], connection))

    def ble_rsp_connection_version_update(self, connection, result):
        logger.info("RSP-Connection Version Update: [%s] (%d)" % (RESULT_CODE[result], connection))

    def ble_rsp_connection_channel_map_get(self, connection, map):
        logger.info("RSP-Connection Channel Map Get: (%d)" % (connection))

    def ble_rsp_connection_channel_map_set(self, connection, result):
        logger.info("RSP-Connection Channel Map Set: [%s] (%d)" % (RESULT_CODE[result], connection))

    def ble_rsp_connection_features_get(self, connection, result):
        logger.info("RSP-Connection Features Get: [%s] (%d)" % (RESULT_CODE[result], connection))

    def ble_rsp_connection_get_status(self, connection):
        logger.info("RSP-Connection Get Status: (%d)" % (connection))

    def ble_rsp_connection_raw_tx(self, connection):
        logger.info("RSP-Connection Raw TX: (%d)" % (connection))

    def ble_rsp_attclient_find_by_type_value(self, connection, result):
        logger.info("RSP-Attribute Client Find By Type Value: [%s] (%d)" % (RESULT_CODE[result], connection))

    def ble_rsp_attclient_read_by_group_type(self, connection, result):
        logger.info("RSP-Attribute Client Read By Group Type - Connection:%d - [%s]" % (connection, RESULT_CODE[result]))

    def ble_rsp_attclient_read_by_type(self, connection, result):
        logger.info("RSP-Attribute Client Read By Type: [%s] (%d)" % (RESULT_CODE[result], connection))

    def ble_rsp_attclient_find_information(self, connection, result):
        logger.info("RSP-Attribute Client Find Information: [%s] (%d)" % (RESULT_CODE[result], connection))

    def ble_rsp_attclient_read_by_handle(self, connection, result):
        logger.info("RSP-Attribute Client Read By Handle: [%s] (%d)" % (RESULT_CODE[result], connection))

    def ble_rsp_attclient_attribute_write(self, connection, result):
        logger.info("RSP-Attribute Client Attribute Write: [%s] (%d)" % (RESULT_CODE[result], connection))

    def ble_rsp_attclient_write_command(self, connection, result):
        logger.info("RSP-Attribute Client Write Command: [%s] (%d)" % (RESULT_CODE[result], connection))

    def ble_rsp_attclient_indicate_confirm(self, result):
        logger.info("RSP-Attribute Client Indicate Confirm: [%s]" % RESULT_CODE[result])

    def ble_rsp_attclient_read_long(self, connection, result):
        logger.info("RSP-Attribute Client Read Long: [%s] (%d)" % (RESULT_CODE[result], connection))

    def ble_rsp_attclient_prepare_write(self, connection, result):
        logger.info("RSP-Attribute Client Prepare Write: [%s] (%d)" % (RESULT_CODE[result], connection))

    def ble_rsp_attclient_execute_write(self, connection, result):
        logger.info("RSP-Attribute Client Execute Write: [%s] (%d)" % (RESULT_CODE[result], connection))

    def ble_rsp_attclient_read_multiple(self, connection, result):
        logger.info("RSP-Attribute Client Read Multiple: [%s] (%d)" % (RESULT_CODE[result], connection))

    def ble_rsp_sm_encrypt_start(self, handle, result):
        logger.info("RSP-SM Encryption Start: [%s] (%d)" % (RESULT_CODE[result], handle))

    def ble_rsp_sm_set_bondable_mode(self):
        logger.info("RSP-SM Bondable Mode")

    def ble_rsp_sm_delete_bonding(self, result):
        logger.info("RSP-SM Delete Bonding: [%s]" % (RESULT_CODE[result]))

    def ble_rsp_sm_set_parameters(self):
        logger.info("RSP-SM Set Parameters")

    def ble_rsp_sm_passkey_entry(self, result):
        logger.info("RSP-SM Passkey Entry: [%s]" % (RESULT_CODE[result]))

    def ble_rsp_sm_get_bonds(self, bonds):
        logger.info("RSP-SM Get Bonds")

    def ble_rsp_sm_set_oob_data(self):
        logger.info("RSP-SM Set OOB Data")

    def ble_rsp_gap_set_privacy_flags(self):
        logger.info("RSP-GAP Set Privacy Flags")

    def ble_rsp_gap_set_mode(self, result):
        logger.info("RSP-GAP Set Mode: [%s]" % (RESULT_CODE[result]))

    def ble_rsp_gap_discover(self, result):
        logger.info("RSP-GAP Discover: [%s]" % RESULT_CODE[result])

    def ble_rsp_gap_connect_direct(self, result, connection_handle):
        logger.info("RSP-GAP Connect Direct: [%s] (%d)" % (RESULT_CODE[result], connection_handle))

    def ble_rsp_gap_end_procedure(self, result):
        logger.info("RSP-GAP End Procedure: [%s]" % (RESULT_CODE[result]))

    def ble_rsp_gap_connect_selective(self, result, connection_handle):
        logger.info("RSP-GAP Connect Selective: [%s] (%d)" % (RESULT_CODE[result], connection_handle))

    def ble_rsp_gap_set_filtering(self, result):
        logger.info("RSP-GAP Set Filtering: [%s]" % (RESULT_CODE[result]))

    def ble_rsp_gap_set_scan_parameters(self, result):
        logger.info("RSP-GAP Set Scan Parameters: [%s]" % (RESULT_CODE[result]))

    def ble_rsp_gap_set_adv_parameters(self, result):
        logger.info("RSP-GAP Set Advertisement Parameters: [%s]" % (RESULT_CODE[result]))

    def ble_rsp_gap_set_adv_data(self, result):
        logger.info("RSP-GAP Set Advertisement Data: [%s]" % (RESULT_CODE[result]))

    def ble_rsp_gap_set_directed_connectable_mode(self, result):
        logger.info("RSP-GAP Set Directed Connectable Mode: [%s]" % (RESULT_CODE[result]))

    def ble_rsp_hardware_io_port_config_irq(self, result):
        logger.info("RSP-Hardware IO Port Config IRQ: [%s]" % (RESULT_CODE[result]))

    def ble_rsp_hardware_set_soft_timer(self, result):
        logger.info("RSP-Hardware Set Soft Timer: [%s]" % (RESULT_CODE[result]))

    def ble_rsp_hardware_adc_read(self, result):
        logger.info("RSP-Hardware ADC Read: [%s]" % (RESULT_CODE[result]))

    def ble_rsp_hardware_io_port_config_direction(self, result):
        logger.info("RSP-Hardware IO Port Config Direction: [%s]" % (RESULT_CODE[result]))

    def ble_rsp_hardware_io_port_config_function(self, result):
        logger.info("RSP-Hardware IO Port Config Function: [%s]" % (RESULT_CODE[result]))

    def ble_rsp_hardware_io_port_config_pull(self, result):
        logger.info("RSP-Hardware IO Port Config Pullup: [%s]" % (RESULT_CODE[result]))

    def ble_rsp_hardware_io_port_write(self, result):
        logger.info("RSP-Hardware IO Port Write: [%s]" % (RESULT_CODE[result]))

    def ble_rsp_hardware_io_port_read(self, result, port, data):
        logger.info("RSP-Hardware IO Port Read: [%s]" % (RESULT_CODE[result]))

    def ble_rsp_hardware_spi_config(self, result):
        logger.info("RSP-Hardware SPI Config: [%s]" % (RESULT_CODE[result]))

    def ble_rsp_hardware_spi_transfer(self, result, channel, data):
        logger.info("RSP-Hardware SPI Transfer: [%s] (%d)" % (RESULT_CODE[result], channel))

    def ble_rsp_hardware_i2c_read(self, result, data):
        logger.info("RSP-Hardware I2C Read: [%s]" % (RESULT_CODE[result]))

    def ble_rsp_hardware_i2c_write(self, written):
        logger.info("RSP-Hardware I2C Write: ")

    def ble_rsp_hardware_set_txpower(self):
        logger.info("RSP-Hardware Set TX Power")

    def ble_rsp_hardware_timer_comparator(self, result):
        logger.info("RSP-Hardware Timer Comparator: [%s]" % (RESULT_CODE[result]))

    def ble_rsp_test_phy_tx(self):
        logger.info("RSP-Test Phy TX")

    def ble_rsp_test_phy_rx(self):
        logger.info("RSP-Test Phy RX")

    def ble_rsp_test_phy_end(self, counter):
        logger.info("RSP-Test Phy End: %d" % (counter))

    def ble_rsp_test_phy_reset(self):
        logger.info("RSP-Test Phy Reset")

    def ble_rsp_test_get_channel_map(self, channel_map):
        logger.info("RSP-Test Get Channel Map")

    def ble_rsp_test_debug(self, output):
        logger.info("RSP-Test Debug")

    def ble_evt_system_boot(self, major, minor, patch, build, ll_version, protocol_version, hw):
        logger.info("EVT-System Boot - Version:%d.%d.%d.%d - Link Layer Version:%d - Protocol Version:%d - hw:%d" %
                    (major, minor, patch, build, ll_version, protocol_version, hw))

    def ble_evt_system_debug(self, data):
        logger.info("EVT-System Debug:", data)

    def ble_evt_system_endpoint_watermark_rx(self, endpoint, data):
        logger.info("EVT-System Endpoint Watermark RX: %d" % (endpoint))

    def ble_evt_system_endpoint_watermark_tx(self, endpoint, data):
        logger.info("EVT-System Endpoint Watermark TX: %d" % (endpoint))

    def ble_evt_system_script_failure(self, address, reason):
        logger.info("EVT-System Script Failure")

    def ble_evt_system_no_license_key(self):
        logger.info("EVT-System No License Key")

    def ble_evt_flash_ps_key(self, key, value):
        logger.info("EVT-Flash PS Key")

    def ble_evt_attributes_value(self, connection, reason, handle, offset, value):
        logger.info("EVT-Attributes Value - Connection:%d - Reason:[%s] - Handle:%d - Offset:%d - " % (connection, ATTRIBUTE_CHANGE_REASON[reason], handle, offset) + \
            "Value:%s" % ("".join(["%02X" % ord(i) for i in value])))

    def ble_evt_attributes_user_read_request(self, connection, handle, offset, maxsize):
        logger.info("EVT-Attributes User Read Request")

    def ble_evt_attributes_status(self, handle, flags):
        logger.info("EVT-Attributes Status - Handle:%d - Flags:[%s]" % (handle, ATTRIBUTE_STATUS_FLAGS[flags]))

    def ble_evt_connection_status(self, connection, flags, address, address_type, conn_interval, timeout, latency, bonding):
        logger.info("EVT-Connection Status - Handle:%d - Flags:%02X - " % (connection, flags) +
                    "Address:%s - " % ("".join(["%02X" % ord(i) for i in address[::-1]])) +
                    "Address Type:%d - Interval:%d - Timeout:%d - Latency:%d - Bonding:%d" % (address_type, conn_interval, timeout, latency, bonding))

    def ble_evt_connection_version_ind(self, connection, vers_nr, comp_id, sub_vers_nr):
        logger.info("EVT-Connection Version Ind")

    def ble_evt_connection_feature_ind(self, connection, features):
        logger.info("EVT-Connection Feature Ind")

    def ble_evt_connection_raw_rx(self, connection, data):
        logger.info("EVT-Connection Raw RX")

    def ble_evt_connection_disconnected(self, connection, reason):
        logger.info("EVT-Connection Disconnected - Connection:%d - Reason:%s" % (connection, RESULT_CODE[reason]))

    def ble_evt_attclient_indicated(self, connection, attrhandle):
        logger.info("EVT-Attribute Client Indicated - Connection:%d - Attribute Handle:%d" % (connection, attrhandle))

    def ble_evt_attclient_procedure_completed(self, connection, result, chrhandle):
        logger.info("EVT-Attribute Client Procedure Completed - Connection:%d - Result:[%s] - End Characteristic Handle:%d" %
                    (connection, RESULT_CODE[result], chrhandle))

    def ble_evt_attclient_group_found(self, connection, start, end, uuid):
        logger.info("EVT-Attribute Client Group Found - Connection:%d - Start Handle:%d - End Handle:%d - " % (connection, start, end) +
                    "UUID:" + "".join(["%02X" % ord(i) for i in uuid[::-1]]))

    def ble_evt_attclient_attribute_found(self, connection, chrdecl, value, properties, uuid):
        logger.info("EVT-Attribute Client Attribute Found")

    def ble_evt_attclient_find_information_found(self, connection, chrhandle, uuid):
        logger.info("EVT-Attribute Client Find Information Found - Connection:%d - Handle:%d - " % (connection, chrhandle) +
                    "UUID:" + "".join(["\\x%02X" % ord(i) for i in uuid[::-1]]))

    def ble_evt_attclient_attribute_value(self, connection, atthandle, type, value):
        logger.info("EVT-Attribute Client Attribute Value - Connection:%d - Handle:%d - Type:%d - Value:%s" %
                    (connection, atthandle, type, "".join(["%02x" % ord(i) for i in value])))

    def ble_evt_attclient_read_multiple_response(self, connection, handles):
        logger.info("EVT-Attribute Client Read Multiple Response")

    def ble_evt_sm_smp_data(self, handle, packet, data):
        logger.info("EVT-SM SMP Data")

    def ble_evt_sm_bonding_fail(self, handle, result):
        logger.info("EVT-SM Bonding Fail: [%s]" % (RESULT_CODE[result]))

    def ble_evt_sm_passkey_display(self, handle, passkey):
        logger.info("EVT-SM Passkey Display")

    def ble_evt_sm_passkey_request(self, handle):
        logger.info("EVT-SM Passkey Request")

    def ble_evt_sm_bond_status(self, bond, keysize, mitm, keys):
        logger.info("EVT-SM Bond Status - Bond:%d - Key Size:%d - MITM:%d - Keys Used Mask:%02X" %
                    (bond, keysize, mitm, keys))

    def ble_evt_gap_scan_response(self, rssi, packet_type, sender, address_type, bond, data):
        logger.info("EVT-GAP Scan Response - RSSI:%d - Packet Type:%d - " % (rssi, packet_type) +
                    "Sender:%02x:%02x:%02x:%02x:%02x:%02x - " % tuple([ord(i) for i in sender[::-1]]) +
                    "Address Type:%d - Bond:%d - Data:" % (address_type, bond) +
                    "".join((["%02x"% ord(i) for i in data])))

    def ble_evt_gap_mode_changed(self, discover, connect):
        logger.info("EVT-GAP Mode Changed")

    def ble_evt_hardware_io_port_status(self, timestamp, port, irq, state):
        logger.info("EVT-Hardware IO Port Status")

    def ble_evt_hardware_soft_timer(self, handle):
        logger.info("EVT-Hardware Soft Timer")

    def ble_evt_hardware_adc_result(self, input, value):
        logger.info("EVT-Hardware ADC Result")
