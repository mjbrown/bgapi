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
        self._timeout = timeout
        if not callbacks:
            self._callbacks = BlueGigaCallbacks()
        else:
            self._callbacks = callbacks

    def _run(self):
        self.rx_buffer = ""
        while (self._continue):
            self.poll_serial(bytes=1)
        self._serial.close()

    def poll_serial(self, bytes=MAX_BGAPI_PACKET_SIZE):
        self.rx_buffer += self._serial.read(bytes)
        while len(self.rx_buffer) >= 2:
            expected_length = 4 + (ord(self.rx_buffer[0]) & 0x07)*256 + ord(self.rx_buffer[1])
            if len(self.rx_buffer) < expected_length:
                break
            else:
                self.parse_bgapi_packet(self.rx_buffer[:expected_length], self._callbacks)
                self.rx_buffer = self.rx_buffer[expected_length:]

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

    def send_command(self, cmd):
        """
        It is easier to use the ble_cmd methods, use this if you know how to compose your own BGAPI packets.
        :param cmd: Data to be sent over serial
        :return:
        """
        logger.debug('=>[ ' + ' '.join(['%02X' % ord(b) for b in cmd ]) + ' ]')
        self._serial.write(cmd)

    def ble_cmd_system_reset(self, boot_in_dfu):
        self.send_command(struct.pack('<4BB', 0, 1, 0, 0, boot_in_dfu))
    def ble_cmd_system_hello(self):
        self.send_command(struct.pack('<4B', 0, 0, 0, 1))
    def ble_cmd_system_address_get(self):
        self.send_command(struct.pack('<4B', 0, 0, 0, 2))
    def ble_cmd_system_reg_write(self, address, value):
        self.send_command(struct.pack('<4BHB', 0, 3, 0, 3, address, value))
    def ble_cmd_system_reg_read(self, address):
        self.send_command(struct.pack('<4BH', 0, 2, 0, 4, address))
    def ble_cmd_system_get_counters(self):
        self.send_command(struct.pack('<4B', 0, 0, 0, 5))
    def ble_cmd_system_get_connections(self):
        self.send_command(struct.pack('<4B', 0, 0, 0, 6))
    def ble_cmd_system_read_memory(self, address, length):
        self.send_command(struct.pack('<4BIB', 0, 5, 0, 7, address, length))
    def ble_cmd_system_get_info(self):
        self.send_command(struct.pack('<4B', 0, 0, 0, 8))
    def ble_cmd_system_endpoint_tx(self, endpoint, data):
        self.send_command(struct.pack('<4BBB' + str(len(data)) + 's', 0, 2 + len(data), 0, 9, endpoint, len(data), data))
    def ble_cmd_system_whitelist_append(self, address, address_type):
        self.send_command(struct.pack('<4B6sB', 0, 7, 0, 10, address, address_type))
    def ble_cmd_system_whitelist_remove(self, address, address_type):
        self.send_command(struct.pack('<4B6sB', 0, 7, 0, 11, address, address_type))
    def ble_cmd_system_whitelist_clear(self):
        self.send_command(struct.pack('<4B', 0, 0, 0, 12))
    def ble_cmd_system_endpoint_rx(self, endpoint, size):
        self.send_command(struct.pack('<4BBB', 0, 2, 0, 13, endpoint, size))
    def ble_cmd_system_endpoint_set_watermarks(self, endpoint, rx, tx):
        self.send_command(struct.pack('<4BBBB', 0, 3, 0, 14, endpoint, rx, tx))
    def ble_cmd_flash_ps_defrag(self):
        self.send_command(struct.pack('<4B', 0, 0, 1, 0))
    def ble_cmd_flash_ps_dump(self):
        self.send_command(struct.pack('<4B', 0, 0, 1, 1))
    def ble_cmd_flash_ps_erase_all(self):
        self.send_command(struct.pack('<4B', 0, 0, 1, 2))
    def ble_cmd_flash_ps_save(self, key, value):
        self.send_command(struct.pack('<4BHB' + str(len(value)) + 's', 0, 3 + len(value), 1, 3, key, len(value), value))
    def ble_cmd_flash_ps_load(self, key):
        self.send_command(struct.pack('<4BH', 0, 2, 1, 4, key))
    def ble_cmd_flash_ps_erase(self, key):
        self.send_command(struct.pack('<4BH', 0, 2, 1, 5, key))
    def ble_cmd_flash_erase_page(self, page):
        self.send_command(struct.pack('<4BB', 0, 1, 1, 6, page))
    def ble_cmd_flash_write_words(self, address, words):
        self.send_command(struct.pack('<4BHB' + str(len(words)) + 's', 0, 3 + len(words), 1, 7, address, len(words), words))
    def ble_cmd_attributes_write(self, handle, offset, value):
        self.send_command(struct.pack('<4BHBB' + str(len(value)) + 's', 0, 4 + len(value), 2, 0, handle, offset, len(value), value))
    def ble_cmd_attributes_read(self, handle, offset):
        self.send_command(struct.pack('<4BHH', 0, 4, 2, 1, handle, offset))
    def ble_cmd_attributes_read_type(self, handle):
        self.send_command(struct.pack('<4BH', 0, 2, 2, 2, handle))
    def ble_cmd_attributes_user_read_response(self, connection, att_error, value):
        self.send_command(struct.pack('<4BBBB' + str(len(value)) + 's', 0, 3 + len(value), 2, 3, connection, att_error, len(value), value))
    def ble_cmd_attributes_user_write_response(self, connection, att_error):
        self.send_command(struct.pack('<4BBB', 0, 2, 2, 4, connection, att_error))
    def ble_cmd_connection_disconnect(self, connection):
        self.send_command(struct.pack('<4BB', 0, 1, 3, 0, connection))
    def ble_cmd_connection_get_rssi(self, connection):
        self.send_command(struct.pack('<4BB', 0, 1, 3, 1, connection))
    def ble_cmd_connection_update(self, connection, interval_min, interval_max, latency, timeout):
        self.send_command(struct.pack('<4BBHHHH', 0, 9, 3, 2, connection, interval_min, interval_max, latency, timeout))
    def ble_cmd_connection_version_update(self, connection):
        self.send_command(struct.pack('<4BB', 0, 1, 3, 3, connection))
    def ble_cmd_connection_channel_map_get(self, connection):
        self.send_command(struct.pack('<4BB', 0, 1, 3, 4, connection))
    def ble_cmd_connection_channel_map_set(self, connection, map):
        self.send_command(struct.pack('<4BBB' + str(len(map)) + 's', 0, 2 + len(map), 3, 5, connection, len(map), map))
    def ble_cmd_connection_features_get(self, connection):
        self.send_command(struct.pack('<4BB', 0, 1, 3, 6, connection))
    def ble_cmd_connection_get_status(self, connection):
        self.send_command(struct.pack('<4BB', 0, 1, 3, 7, connection))
    def ble_cmd_connection_raw_tx(self, connection, data):
        self.send_command(struct.pack('<4BBB' + str(len(data)) + 's', 0, 2 + len(data), 3, 8, connection, len(data), data))
    def ble_cmd_attclient_find_by_type_value(self, connection, start, end, uuid, value):
        self.send_command(struct.pack('<4BBHHHB' + str(len(value)) + 's', 0, 8 + len(value), 4, 0, connection, start, end, uuid, len(value), value))
    def ble_cmd_attclient_read_by_group_type(self, connection, start, end, uuid): # =>[ 00 08 04 01 00 01 00 FF FF 02 00 28 ]
        self.send_command(struct.pack('<4BBHHB' + str(len(uuid)) + 's', 0, 6 + len(uuid), 4, 1, connection, start, end, len(uuid), uuid))
    def ble_cmd_attclient_read_by_type(self, connection, start, end, uuid):
        self.send_command(struct.pack('<4BBHHB' + str(len(uuid)) + 's', 0, 6 + len(uuid), 4, 2, connection, start, end, len(uuid), uuid))
    def ble_cmd_attclient_find_information(self, connection, start, end):
        self.send_command(struct.pack('<4BBHH', 0, 5, 4, 3, connection, start, end))
    def ble_cmd_attclient_read_by_handle(self, connection, chrhandle):
        self.send_command(struct.pack('<4BBH', 0, 3, 4, 4, connection, chrhandle))
    def ble_cmd_attclient_attribute_write(self, connection, atthandle, data):
        self.send_command(struct.pack('<4BBHB' + str(len(data)) + 's', 0, 4 + len(data), 4, 5, connection, atthandle, len(data), data))
    def ble_cmd_attclient_write_command(self, connection, atthandle, data):
        self.send_command(struct.pack('<4BBHB' + str(len(data)) + 's', 0, 4 + len(data), 4, 6, connection, atthandle, len(data), data))
    def ble_cmd_attclient_indicate_confirm(self, connection):
        self.send_command(struct.pack('<4BB', 0, 1, 4, 7, connection))
    def ble_cmd_attclient_read_long(self, connection, chrhandle):
        self.send_command(struct.pack('<4BBH', 0, 3, 4, 8, connection, chrhandle))
    def ble_cmd_attclient_prepare_write(self, connection, atthandle, offset, data):
        self.send_command(struct.pack('<4BBHHB' + str(len(data)) + 's', 0, 6 + len(data), 4, 9, connection, atthandle, offset, len(data), data))
    def ble_cmd_attclient_execute_write(self, connection, commit):
        self.send_command(struct.pack('<4BBB', 0, 2, 4, 10, connection, commit))
    def ble_cmd_attclient_read_multiple(self, connection, handles):
        self.send_command(struct.pack('<4BBB' + str(len(handles)) + 's', 0, 2 + len(handles), 4, 11, connection, len(handles), handles))
    def ble_cmd_sm_encrypt_start(self, handle, bonding):
        self.send_command(struct.pack('<4BBB', 0, 2, 5, 0, handle, bonding))
    def ble_cmd_sm_set_bondable_mode(self, bondable):
        self.send_command(struct.pack('<4BB', 0, 1, 5, 1, bondable))
    def ble_cmd_sm_delete_bonding(self, handle):
        self.send_command(struct.pack('<4BB', 0, 1, 5, 2, handle))
    def ble_cmd_sm_set_parameters(self, mitm, min_key_size, io_capabilities):
        self.send_command(struct.pack('<4BBBB', 0, 3, 5, 3, mitm, min_key_size, io_capabilities))
    def ble_cmd_sm_passkey_entry(self, handle, passkey):
        self.send_command(struct.pack('<4BBI', 0, 5, 5, 4, handle, passkey))
    def ble_cmd_sm_get_bonds(self):
        self.send_command(struct.pack('<4B', 0, 0, 5, 5))
    def ble_cmd_sm_set_oob_data(self, oob):
        self.send_command(struct.pack('<4BB' + str(len(oob)) + 's', 0, 1 + len(oob), 5, 6, len(oob), oob))
    def ble_cmd_gap_set_privacy_flags(self, peripheral_privacy, central_privacy):
        self.send_command(struct.pack('<4BBB', 0, 2, 6, 0, peripheral_privacy, central_privacy))
    def ble_cmd_gap_set_mode(self, discover, connect):
        self.send_command(struct.pack('<4BBB', 0, 2, 6, 1, discover, connect))
    def ble_cmd_gap_discover(self, mode):
        self.send_command(struct.pack('<4BB', 0, 1, 6, 2, mode))
    def ble_cmd_gap_connect_direct(self, address, addr_type, conn_interval_min, conn_interval_max, timeout, latency):
        self.send_command(struct.pack('<4B6sBHHHH', 0, 15, 6, 3, address, addr_type, conn_interval_min, conn_interval_max, timeout, latency))
    def ble_cmd_gap_end_procedure(self):
        self.send_command(struct.pack('<4B', 0, 0, 6, 4))
    def ble_cmd_gap_connect_selective(self, conn_interval_min, conn_interval_max, timeout, latency):
        self.send_command(struct.pack('<4BHHHH', 0, 8, 6, 5, conn_interval_min, conn_interval_max, timeout, latency))
    def ble_cmd_gap_set_filtering(self, scan_policy, adv_policy, scan_duplicate_filtering):
        self.send_command(struct.pack('<4BBBB', 0, 3, 6, 6, scan_policy, adv_policy, scan_duplicate_filtering))
    def ble_cmd_gap_set_scan_parameters(self, scan_interval, scan_window, active):
        self.send_command(struct.pack('<4BHHB', 0, 5, 6, 7, scan_interval, scan_window, active))
    def ble_cmd_gap_set_adv_parameters(self, adv_interval_min, adv_interval_max, adv_channels):
        self.send_command(struct.pack('<4BHHB', 0, 5, 6, 8, adv_interval_min, adv_interval_max, adv_channels))
    def ble_cmd_gap_set_adv_data(self, set_scanrsp, adv_data):
        self.send_command(struct.pack('<4BBB' + str(len(adv_data)) + 's', 0, 2 + len(adv_data), 6, 9, set_scanrsp, len(adv_data), adv_data))
    def ble_cmd_gap_set_directed_connectable_mode(self, address, addr_type):
        self.send_command(struct.pack('<4B6sB', 0, 7, 6, 10, b''.join(chr(i) for i in address), addr_type))
    def ble_cmd_hardware_io_port_config_irq(self, port, enable_bits, falling_edge):
        self.send_command(struct.pack('<4BBBB', 0, 3, 7, 0, port, enable_bits, falling_edge))
    def ble_cmd_hardware_set_soft_timer(self, time, handle, single_shot):
        self.send_command(struct.pack('<4BIBB', 0, 6, 7, 1, time, handle, single_shot))
    def ble_cmd_hardware_adc_read(self, input, decimation, reference_selection):
        self.send_command(struct.pack('<4BBBB', 0, 3, 7, 2, input, decimation, reference_selection))
    def ble_cmd_hardware_io_port_config_direction(self, port, direction):
        self.send_command(struct.pack('<4BBB', 0, 2, 7, 3, port, direction))
    def ble_cmd_hardware_io_port_config_function(self, port, function):
        self.send_command(struct.pack('<4BBB', 0, 2, 7, 4, port, function))
    def ble_cmd_hardware_io_port_config_pull(self, port, tristate_mask, pull_up):
        self.send_command(struct.pack('<4BBBB', 0, 3, 7, 5, port, tristate_mask, pull_up))
    def ble_cmd_hardware_io_port_write(self, port, mask, data):
        self.send_command(struct.pack('<4BBBB', 0, 3, 7, 6, port, mask, data))
    def ble_cmd_hardware_io_port_read(self, port, mask):
        self.send_command(struct.pack('<4BBB', 0, 2, 7, 7, port, mask))
    def ble_cmd_hardware_spi_config(self, channel, polarity, phase, bit_order, baud_e, baud_m):
        self.send_command(struct.pack('<4BBBBBBB', 0, 6, 7, 8, channel, polarity, phase, bit_order, baud_e, baud_m))
    def ble_cmd_hardware_spi_transfer(self, channel, data):
        self.send_command(struct.pack('<4BBB' + str(len(data)) + 's', 0, 2 + len(data), 7, 9, channel, len(data), data))
    def ble_cmd_hardware_i2c_read(self, address, stop, length):
        self.send_command(struct.pack('<4BBBB', 0, 3, 7, 10, address, stop, length))
    def ble_cmd_hardware_i2c_write(self, address, stop, data):
        self.send_command(struct.pack('<4BBBB' + str(len(data)) + 's', 0, 3 + len(data), 7, 11, address, stop, len(data), data))
    def ble_cmd_hardware_set_txpower(self, power):
        self.send_command(struct.pack('<4BB', 0, 1, 7, 12, power))
    def ble_cmd_hardware_timer_comparator(self, timer, channel, mode, comparator_value):
        self.send_command(struct.pack('<4BBBBH', 0, 5, 7, 13, timer, channel, mode, comparator_value))
    def ble_cmd_test_phy_tx(self, channel, length, type):
        self.send_command(struct.pack('<4BBBB', 0, 3, 8, 0, channel, length, type))
    def ble_cmd_test_phy_rx(self, channel):
        self.send_command(struct.pack('<4BB', 0, 1, 8, 1, channel))
    def ble_cmd_test_phy_end(self):
        self.send_command(struct.pack('<4B', 0, 0, 8, 2))
    def ble_cmd_test_phy_reset(self):
        self.send_command(struct.pack('<4B', 0, 0, 8, 3))
    def ble_cmd_test_get_channel_map(self):
        self.send_command(struct.pack('<4B', 0, 0, 8, 4))
    def ble_cmd_test_debug(self, input):
        self.send_command(struct.pack('<4BB' + str(len(input)) + 's', 0, 1 + len(input), 8, 5, len(input), input))

    def parse_bgapi_packet(self, packet, callbacks):
        logger.debug('<=[ ' + ' '.join(['%02X' % ord(b) for b in packet ]) + ' ]')
        packet_type = ord(packet[0]) & 0x80
        technology_type = ord(packet[0]) & 0x78
        #payload_length = ord(packet[1])
        packet_class = ord(packet[2])
        packet_command = ord(packet[3])
        rx_payload = packet[4:]
        if technology_type:
            raise ValueError("Unsupported techlogy type: 0x%02x" % technology_type)
        if packet_type == 0x00:
            # 0x00 = BLE response packet
            if packet_class == 0:
                if packet_command == 0: # ble_rsp_system_reset
                    callbacks.ble_rsp_system_reset()
                elif packet_command == 1: # ble_rsp_system_hello
                    callbacks.ble_rsp_system_hello()
                elif packet_command == 2: # ble_rsp_system_address_get
                    callbacks.ble_rsp_system_address_get(address=rx_payload)
                elif packet_command == 3: # ble_rsp_system_reg_write
                    result = struct.unpack('<H', rx_payload[:2])[0]
                    callbacks.ble_rsp_system_reg_write(result=result)
                elif packet_command == 4: # ble_rsp_system_reg_read
                    address, value = struct.unpack('<HB', rx_payload[:3])
                    callbacks.ble_rsp_system_reg_read(address=address, value=value)
                elif packet_command == 5: # ble_rsp_system_get_counters
                    txok, txretry, rxok, rxfail, mbuf = struct.unpack('<BBBBB', rx_payload[:5])
                    callbacks.ble_rsp_system_get_counters(txok=txok, txretry=txretry, rxok=rxok, rxfail=rxfail, mbuf=mbuf)
                elif packet_command == 6: # ble_rsp_system_get_connections
                    maxconn = struct.unpack('<B', rx_payload[:1])[0]
                    callbacks.ble_rsp_system_get_connections(maxconn=maxconn)
                elif packet_command == 7: # ble_rsp_system_read_memory
                    address, data_len = struct.unpack('<IB', rx_payload[:5])
                    callbacks.ble_rsp_system_read_memory(address=address, data=rx_payload[5:])
                elif packet_command == 8: # ble_rsp_system_get_info
                    major, minor, patch, build, ll_version, protocol_version, hw = struct.unpack('<HHHHHBB', rx_payload[:12])
                    callbacks.ble_rsp_system_get_info(major=major, minor=minor, patch=patch, build=build, ll_version=ll_version, protocol_version=protocol_version, hw=hw)
                elif packet_command == 9: # ble_rsp_system_endpoint_tx
                    result = struct.unpack('<H', rx_payload[:2])[0]
                    callbacks.ble_rsp_system_endpoint_tx(result=result)
                elif packet_command == 10: # ble_rsp_system_whitelist_append
                    result = struct.unpack('<H', rx_payload[:2])[0]
                    callbacks.ble_rsp_system_whitelist_append(result=result)
                elif packet_command == 11: # ble_rsp_system_whitelist_remove
                    result = struct.unpack('<H', rx_payload[:2])[0]
                    callbacks.ble_rsp_system_whitelist_remove(result=result)
                elif packet_command == 12: # ble_rsp_system_whitelist_clear
                    callbacks.ble_rsp_system_whitelist_clear()
                elif packet_command == 13: # ble_rsp_system_endpoint_rx
                    result, data_len = struct.unpack('<HB', rx_payload[:3])
                    callbacks.ble_rsp_system_endpoint_rx(result=result, data=rx_payload[3:])
                elif packet_command == 14: # ble_rsp_system_endpoint_set_watermarks
                    result = struct.unpack('<H', rx_payload[:2])[0]
                    callbacks.ble_rsp_system_endpoint_set_watermarks(result=result)
            elif packet_class == 1:
                if packet_command == 0: # ble_rsp_flash_ps_defrag
                    callbacks.ble_rsp_flash_ps_defrag()
                elif packet_command == 1: # ble_rsp_flash_ps_dump
                    callbacks.ble_rsp_flash_ps_dump()
                elif packet_command == 2: # ble_rsp_flash_ps_erase_all
                    callbacks.ble_rsp_flash_ps_erase_all()
                elif packet_command == 3: # ble_rsp_flash_ps_save
                    result = struct.unpack('<H', rx_payload[:2])[0]
                    callbacks.ble_rsp_flash_ps_save(result=result)
                elif packet_command == 4: # ble_rsp_flash_ps_load
                    result, value_len = struct.unpack('<HB', rx_payload[:3])
                    callbacks.ble_rsp_flash_ps_load(result=result, value=rx_payload[3:])
                elif packet_command == 5: # ble_rsp_flash_ps_erase
                    callbacks.ble_rsp_flash_ps_erase()
                elif packet_command == 6: # ble_rsp_flash_erase_page
                    result = struct.unpack('<H', rx_payload[:2])[0]
                    callbacks.ble_rsp_flash_erase_page(result=result)
                elif packet_command == 7: # ble_rsp_flash_write_words
                    callbacks.ble_rsp_flash_write_words()
            elif packet_class == 2:
                if packet_command == 0: # ble_rsp_attributes_write
                    result = struct.unpack('<H', rx_payload[:2])[0]
                    callbacks.ble_rsp_attributes_write(result=result)
                elif packet_command == 1: # ble_rsp_attributes_read
                    handle, offset, result, value_len = struct.unpack('<HHHB', rx_payload[:7])
                    callbacks.ble_rsp_attributes_read(handle=handle, offset=offset, result=result, value=rx_payload[7:])
                elif packet_command == 2: # ble_rsp_attributes_read_type
                    handle, result, value_len = struct.unpack('<HHB', rx_payload[:5])
                    callbacks.ble_rsp_attributes_read_type(handle=handle, result=result, value=rx_payload[5:])
                elif packet_command == 3: # ble_rsp_attributes_user_read_response
                    callbacks.ble_rsp_attributes_user_read_response()
                elif packet_command == 4: # ble_rsp_attributes_user_write_response
                    callbacks.ble_rsp_attributes_user_write_response()
            elif packet_class == 3:
                if packet_command == 0: # ble_rsp_connection_disconnect
                    connection, result = struct.unpack('<BH', rx_payload[:3])
                    callbacks.ble_rsp_connection_disconnect(connection=connection, result=result)
                elif packet_command == 1: # ble_rsp_connection_get_rssi
                    connection, rssi = struct.unpack('<Bb', rx_payload[:2])
                    callbacks.ble_rsp_connection_get_rssi(connection=connection, rssi=rssi)
                elif packet_command == 2: # ble_rsp_connection_update
                    connection, result = struct.unpack('<BH', rx_payload[:3])
                    callbacks.ble_rsp_connection_update(connection=connection, result=result)
                elif packet_command == 3: # ble_rsp_connection_version_update
                    connection, result = struct.unpack('<BH', rx_payload[:3])
                    callbacks.ble_rsp_connection_version_update(connection=connection, result=result)
                elif packet_command == 4: # ble_rsp_connection_channel_map_get
                    connection, map_len = struct.unpack('<BB', rx_payload[:2])
                    callbacks.ble_rsp_connection_channel_map_get(connection=connection, map=rx_payload[2:])
                elif packet_command == 5: # ble_rsp_connection_channel_map_set
                    connection, result = struct.unpack('<BH', rx_payload[:3])
                    callbacks.ble_rsp_connection_channel_map_set(connection=connection, result=result)
                elif packet_command == 6: # ble_rsp_connection_features_get
                    connection, result = struct.unpack('<BH', rx_payload[:3])
                    callbacks.ble_rsp_connection_features_get(connection=connection, result=result)
                elif packet_command == 7: # ble_rsp_connection_get_status
                    connection = struct.unpack('<B', rx_payload[:1])[0]
                    callbacks.ble_rsp_connection_get_status(connection=connection)
                elif packet_command == 8: # ble_rsp_connection_raw_tx
                    connection = struct.unpack('<B', rx_payload[:1])[0]
                    callbacks.ble_rsp_connection_raw_tx(connection=connection)
            elif packet_class == 4:
                if packet_command == 0: # ble_rsp_attclient_find_by_type_value
                    connection, result = struct.unpack('<BH', rx_payload[:3])
                    callbacks.ble_rsp_attclient_find_by_type_value(connection=connection, result=result)
                elif packet_command == 1: # ble_rsp_attclient_read_by_group_type
                    connection, result = struct.unpack('<BH', rx_payload[:3])
                    callbacks.ble_rsp_attclient_read_by_group_type(connection=connection, result=result)
                elif packet_command == 2: # ble_rsp_attclient_read_by_type
                    connection, result = struct.unpack('<BH', rx_payload[:3])
                    callbacks.ble_rsp_attclient_read_by_type(connection=connection, result=result)
                elif packet_command == 3: # ble_rsp_attclient_find_information
                    connection, result = struct.unpack('<BH', rx_payload[:3])
                    callbacks.ble_rsp_attclient_find_information(connection=connection, result=result)
                elif packet_command == 4: # ble_rsp_attclient_read_by_handle
                    connection, result = struct.unpack('<BH', rx_payload[:3])
                    callbacks.ble_rsp_attclient_read_by_handle(connection=connection, result=result)
                elif packet_command == 5: # ble_rsp_attclient_attribute_write
                    connection, result = struct.unpack('<BH', rx_payload[:3])
                    callbacks.ble_rsp_attclient_attribute_write(connection=connection, result=result)
                elif packet_command == 6: # ble_rsp_attclient_write_command
                    connection, result = struct.unpack('<BH', rx_payload[:3])
                    callbacks.ble_rsp_attclient_write_command(connection=connection, result=result)
                elif packet_command == 7: # ble_rsp_attclient_indicate_confirm
                    result = struct.unpack('<H', rx_payload[:2])[0]
                    callbacks.ble_rsp_attclient_indicate_confirm(result=result)
                elif packet_command == 8: # ble_rsp_attclient_read_long
                    connection, result = struct.unpack('<BH', rx_payload[:3])
                    callbacks.ble_rsp_attclient_read_long(connection=connection, result=result)
                elif packet_command == 9: # ble_rsp_attclient_prepare_write
                    connection, result = struct.unpack('<BH', rx_payload[:3])
                    callbacks.ble_rsp_attclient_prepare_write(connection=connection, result=result)
                elif packet_command == 10: # ble_rsp_attclient_execute_write
                    connection, result = struct.unpack('<BH', rx_payload[:3])
                    callbacks.ble_rsp_attclient_execute_write(connection=connection, result=result)
                elif packet_command == 11: # ble_rsp_attclient_read_multiple
                    connection, result = struct.unpack('<BH', rx_payload[:3])
                    callbacks.ble_rsp_attclient_read_multiple(connection=connection, result=result)
            elif packet_class == 5:
                if packet_command == 0: # ble_rsp_sm_encrypt_start
                    handle, result = struct.unpack('<BH', rx_payload[:3])
                    callbacks.ble_rsp_sm_encrypt_start(handle=handle, result=result)
                elif packet_command == 1: # ble_rsp_sm_set_bondable_mode
                    callbacks.ble_rsp_sm_set_bondable_mode()
                elif packet_command == 2: # ble_rsp_sm_delete_bonding
                    result = struct.unpack('<H', rx_payload[:2])[0]
                    callbacks.ble_rsp_sm_delete_bonding(result=result)
                elif packet_command == 3: # ble_rsp_sm_set_parameters
                    callbacks.ble_rsp_sm_set_parameters()
                elif packet_command == 4: # ble_rsp_sm_passkey_entry
                    result = struct.unpack('<H', rx_payload[:2])[0]
                    callbacks.ble_rsp_sm_passkey_entry(result=result)
                elif packet_command == 5: # ble_rsp_sm_get_bonds
                    bonds = struct.unpack('<B', rx_payload[:1])[0]
                    callbacks.ble_rsp_sm_get_bonds(bonds=bonds)
                elif packet_command == 6: # ble_rsp_sm_set_oob_data
                    callbacks.ble_rsp_sm_set_oob_data()
            elif packet_class == 6:
                if packet_command == 0: # ble_rsp_gap_set_privacy_flags
                    callbacks.ble_rsp_gap_set_privacy_flags({  })
                elif packet_command == 1: # ble_rsp_gap_set_mode
                    result = struct.unpack('<H', rx_payload[:2])[0]
                    callbacks.ble_rsp_gap_set_mode(result=result)
                elif packet_command == 2: # ble_rsp_gap_discover
                    result = struct.unpack('<H', rx_payload[:2])[0]
                    callbacks.ble_rsp_gap_discover(result=result)
                elif packet_command == 3: # ble_rsp_gap_connect_direct
                    result, connection_handle = struct.unpack('<HB', rx_payload[:3])
                    callbacks.ble_rsp_gap_connect_direct(result=result, connection_handle=connection_handle)
                elif packet_command == 4: # ble_rsp_gap_end_procedure
                    result = struct.unpack('<H', rx_payload[:2])[0]
                    callbacks.ble_rsp_gap_end_procedure(result=result)
                elif packet_command == 5: # ble_rsp_gap_connect_selective
                    result, connection_handle = struct.unpack('<HB', rx_payload[:3])
                    callbacks.ble_rsp_gap_connect_selective(result=result, connection_handle=connection_handle)
                elif packet_command == 6: # ble_rsp_gap_set_filtering
                    result = struct.unpack('<H', rx_payload[:2])[0]
                    callbacks.ble_rsp_gap_set_filtering(result=result)
                elif packet_command == 7: # ble_rsp_gap_set_scan_parameters
                    result = struct.unpack('<H', rx_payload[:2])[0]
                    callbacks.ble_rsp_gap_set_scan_parameters(result=result)
                elif packet_command == 8: # ble_rsp_gap_set_adv_parameters
                    result = struct.unpack('<H', rx_payload[:2])[0]
                    callbacks.ble_rsp_gap_set_adv_parameters(result=result)
                elif packet_command == 9: # ble_rsp_gap_set_adv_data
                    result = struct.unpack('<H', rx_payload[:2])[0]
                    callbacks.ble_rsp_gap_set_adv_data(result=result)
                elif packet_command == 10: # ble_rsp_gap_set_directed_connectable_mode
                    result = struct.unpack('<H', rx_payload[:2])[0]
                    callbacks.ble_rsp_gap_set_directed_connectable_mode(result=result)
            elif packet_class == 7:
                if packet_command == 0: # ble_rsp_hardware_io_port_config_irq
                    result = struct.unpack('<H', rx_payload[:2])[0]
                    callbacks.ble_rsp_hardware_io_port_config_irq(result=result)
                elif packet_command == 1: # ble_rsp_hardware_set_soft_timer
                    result = struct.unpack('<H', rx_payload[:2])[0]
                    callbacks.ble_rsp_hardware_set_soft_timer(result=result)
                elif packet_command == 2: # ble_rsp_hardware_adc_read
                    result = struct.unpack('<H', rx_payload[:2])[0]
                    callbacks.ble_rsp_hardware_adc_read(result=result)
                elif packet_command == 3: # ble_rsp_hardware_io_port_config_direction
                    result = struct.unpack('<H', rx_payload[:2])[0]
                    callbacks.ble_rsp_hardware_io_port_config_direction(result=result)
                elif packet_command == 4: # ble_rsp_hardware_io_port_config_function
                    result = struct.unpack('<H', rx_payload[:2])[0]
                    callbacks.ble_rsp_hardware_io_port_config_function(result=result)
                elif packet_command == 5: # ble_rsp_hardware_io_port_config_pull
                    result = struct.unpack('<H', rx_payload[:2])[0]
                    callbacks.ble_rsp_hardware_io_port_config_pull(result=result)
                elif packet_command == 6: # ble_rsp_hardware_io_port_write
                    result = struct.unpack('<H', rx_payload[:2])[0]
                    callbacks.ble_rsp_hardware_io_port_write(result=result)
                elif packet_command == 7: # ble_rsp_hardware_io_port_read
                    result, port, data = struct.unpack('<HBB', rx_payload[:4])
                    callbacks.ble_rsp_hardware_io_port_read(result=result, port=port, data=data)
                elif packet_command == 8: # ble_rsp_hardware_spi_config
                    result = struct.unpack('<H', rx_payload[:2])[0]
                    callbacks.ble_rsp_hardware_spi_config(result=result)
                elif packet_command == 9: # ble_rsp_hardware_spi_transfer
                    result, channel, data_len = struct.unpack('<HBB', rx_payload[:4])
                    callbacks.ble_rsp_hardware_spi_transfer(result=result, channel=channel, data=rx_payload[4:])
                elif packet_command == 10: # ble_rsp_hardware_i2c_read
                    result, data_len = struct.unpack('<HB', rx_payload[:3])
                    callbacks.ble_rsp_hardware_i2c_read(result=result, data=rx_payload[3:])
                elif packet_command == 11: # ble_rsp_hardware_i2c_write
                    written = struct.unpack('<B', rx_payload[:1])[0]
                    callbacks.ble_rsp_hardware_i2c_write(written=written)
                elif packet_command == 12: # ble_rsp_hardware_set_txpower
                    callbacks.ble_rsp_hardware_set_txpower()
                elif packet_command == 13: # ble_rsp_hardware_timer_comparator
                    result = struct.unpack('<H', rx_payload[:2])[0]
                    callbacks.ble_rsp_hardware_timer_comparator(result=result)
            elif packet_class == 8:
                if packet_command == 0: # ble_rsp_test_phy_tx
                    callbacks.ble_rsp_test_phy_tx()
                elif packet_command == 1: # ble_rsp_test_phy_rx
                    callbacks.ble_rsp_test_phy_rx()
                elif packet_command == 2: # ble_rsp_test_phy_end
                    counter = struct.unpack('<H', rx_payload[:2])[0]
                    callbacks.ble_rsp_test_phy_end(counter=counter)
                elif packet_command == 3: # ble_rsp_test_phy_reset
                    callbacks.ble_rsp_test_phy_reset()
                elif packet_command == 4: # ble_rsp_test_get_channel_map
                    callbacks.ble_rsp_test_get_channel_map(channel_map=rx_payload[1:])
                elif packet_command == 5: # ble_rsp_test_debug
                    callbacks.ble_rsp_test_debug(output=rx_payload[1:])
        elif packet_type == 0x80:
            # 0x80 = BLE event packet
            if packet_class == 0:
                if packet_command == 0: # ble_evt_system_boot
                    major, minor, patch, build, ll_version, protocol_version, hw = struct.unpack('<HHHHHBB', rx_payload[:12])
                    callbacks.ble_evt_system_boot(major=major, minor=minor, patch=patch, build=build, ll_version=ll_version, protocol_version=protocol_version, hw=hw)
                elif packet_command == 1: # ble_evt_system_debug
                    callbacks.ble_evt_system_debug(data=rx_payload[1:])
                elif packet_command == 2: # ble_evt_system_endpoint_watermark_rx
                    endpoint, data = struct.unpack('<BB', rx_payload[:2])
                    callbacks.ble_evt_system_endpoint_watermark_rx(endpoint=endpoint, data=data)
                elif packet_command == 3: # ble_evt_system_endpoint_watermark_tx
                    endpoint, data = struct.unpack('<BB', rx_payload[:2])
                    callbacks.ble_evt_system_endpoint_watermark_tx(endpoint=endpoint, data=data)
                elif packet_command == 4: # ble_evt_system_script_failure
                    address, reason = struct.unpack('<HH', rx_payload[:4])
                    callbacks.ble_evt_system_script_failure(address=address, reason=reason)
                elif packet_command == 5: # ble_evt_system_no_license_key
                    callbacks.ble_evt_system_no_license_key({  })
            elif packet_class == 1:
                if packet_command == 0: # ble_evt_flash_ps_key
                    key, value_len = struct.unpack('<HB', rx_payload[:3])
                    callbacks.ble_evt_flash_ps_key(key=key, value=rx_payload[3:])
            elif packet_class == 2:
                if packet_command == 0: # ble_evt_attributes_value
                    connection, reason, handle, offset, value_len = struct.unpack('<BBHHB', rx_payload[:7])
                    callbacks.ble_evt_attributes_value(connection=connection, reason=reason, handle=handle, offset=offset, value=rx_payload[7:])
                elif packet_command == 1: # ble_evt_attributes_user_read_request
                    connection, handle, offset, maxsize = struct.unpack('<BHHB', rx_payload[:6])
                    callbacks.ble_evt_attributes_user_read_request(connection=connection, handle=handle, offset=offset, maxsize=maxsize)
                elif packet_command == 2: # ble_evt_attributes_status
                    handle, flags = struct.unpack('<HB', rx_payload[:3])
                    callbacks.ble_evt_attributes_status(handle=handle, flags=flags)
            elif packet_class == 3:
                if packet_command == 0: # ble_evt_connection_status
                    connection, flags, address, address_type, conn_interval, timeout, latency, bonding = struct.unpack('<BB6sBHHHB', rx_payload[:16])
                    callbacks.ble_evt_connection_status(connection=connection, flags=flags, address=address, address_type=address_type, conn_interval=conn_interval, timeout=timeout, latency=latency, bonding=bonding)
                elif packet_command == 1: # ble_evt_connection_version_ind
                    connection, vers_nr, comp_id, sub_vers_nr = struct.unpack('<BBHH', rx_payload[:6])
                    callbacks.ble_evt_connection_version_ind(connection=connection, vers_nr=vers_nr, comp_id=comp_id, sub_vers_nr=sub_vers_nr)
                elif packet_command == 2: # ble_evt_connection_feature_ind
                    connection, features_len = struct.unpack('<BB', rx_payload[:2])
                    features_data = [ord(b) for b in rx_payload[2:]]
                    callbacks.ble_evt_connection_feature_ind(connection=connection, features=features_data)
                elif packet_command == 3: # ble_evt_connection_raw_rx
                    connection, data_len = struct.unpack('<BB', rx_payload[:2])
                    callbacks.ble_evt_connection_raw_rx(connection=connection, data=rx_payload[2:])
                elif packet_command == 4: # ble_evt_connection_disconnected
                    connection, reason = struct.unpack('<BH', rx_payload[:3])
                    callbacks.ble_evt_connection_disconnected(connection=connection, reason=reason)
            elif packet_class == 4:
                if packet_command == 0: # ble_evt_attclient_indicated
                    connection, attrhandle = struct.unpack('<BH', rx_payload[:3])
                    callbacks.ble_evt_attclient_indicated(connection=connection, attrhandle=attrhandle)
                elif packet_command == 1: # ble_evt_attclient_procedure_completed
                    connection, result, chrhandle = struct.unpack('<BHH', rx_payload[:5])
                    callbacks.ble_evt_attclient_procedure_completed(connection=connection, result=result, chrhandle=chrhandle)
                elif packet_command == 2: # ble_evt_attclient_group_found
                    connection, start, end, uuid_len = struct.unpack('<BHHB', rx_payload[:6])
                    callbacks.ble_evt_attclient_group_found(connection=connection, start=start, end=end, uuid=rx_payload[6:])
                elif packet_command == 3: # ble_evt_attclient_attribute_found
                    connection, chrdecl, value, properties, uuid_len = struct.unpack('<BHHBB', rx_payload[:7])
                    callbacks.ble_evt_attclient_attribute_found(connection=connection, chrdecl=chrdecl, value=value, properties=properties, uuid=rx_payload[7:])
                elif packet_command == 4: # ble_evt_attclient_find_information_found
                    connection, chrhandle, uuid_len = struct.unpack('<BHB', rx_payload[:4])
                    callbacks.ble_evt_attclient_find_information_found(connection=connection, chrhandle=chrhandle, uuid=rx_payload[4:])
                elif packet_command == 5: # ble_evt_attclient_attribute_value
                    connection, atthandle, type, value_len = struct.unpack('<BHBB', rx_payload[:5])
                    callbacks.ble_evt_attclient_attribute_value(connection=connection, atthandle=atthandle, type=type, value=rx_payload[5:])
                elif packet_command == 6: # ble_evt_attclient_read_multiple_response
                    connection, handles_len = struct.unpack('<BB', rx_payload[:2])
                    callbacks.ble_evt_attclient_read_multiple_response(connection=connection, handles=rx_payload[2:])
            elif packet_class == 5:
                if packet_command == 0: # ble_evt_sm_smp_data
                    handle, packet, data_len = struct.unpack('<BBB', rx_payload[:3])
                    callbacks.ble_evt_sm_smp_data(handle=handle, packet=packet, data=rx_payload[3:])
                elif packet_command == 1: # ble_evt_sm_bonding_fail
                    handle, result = struct.unpack('<BH', rx_payload[:3])
                    callbacks.ble_evt_sm_bonding_fail(handle=handle, result=result)
                elif packet_command == 2: # ble_evt_sm_passkey_display
                    handle, passkey = struct.unpack('<BI', rx_payload[:5])
                    callbacks.ble_evt_sm_passkey_display(handle=handle, passkey=passkey)
                elif packet_command == 3: # ble_evt_sm_passkey_request
                    handle = struct.unpack('<B', rx_payload[:1])[0]
                    callbacks.ble_evt_sm_passkey_request(handle=handle)
                elif packet_command == 4: # ble_evt_sm_bond_status
                    bond, keysize, mitm, keys = struct.unpack('<BBBB', rx_payload[:4])
                    callbacks.ble_evt_sm_bond_status(bond=bond, keysize=keysize, mitm=mitm, keys=keys)
            elif packet_class == 6:
                if packet_command == 0: # ble_evt_gap_scan_response
                    rssi, packet_type, sender, address_type, bond, data_len = struct.unpack('<bB6sBBB', rx_payload[:11])
                    callbacks.ble_evt_gap_scan_response(rssi=rssi, packet_type=packet_type, sender=sender,
                                                        address_type=address_type, bond=bond, data=rx_payload[11:] )
                elif packet_command == 1: # ble_evt_gap_mode_changed
                    discover, connect = struct.unpack('<BB', rx_payload[:2])
                    callbacks.ble_evt_gap_mode_changed(discover=discover, connect=connect)
            elif packet_class == 7:
                if packet_command == 0: # ble_evt_hardware_io_port_status
                    timestamp, port, irq, state = struct.unpack('<IBBB', rx_payload[:7])
                    callbacks.ble_evt_hardware_io_port_status(timestamp=timestamp, port=port, irq=irq, state=state)
                elif packet_command == 1: # ble_evt_hardware_soft_timer
                    handle = struct.unpack('<B', rx_payload[:1])[0]
                    callbacks.ble_evt_hardware_soft_timer(handle=handle)
                elif packet_command == 2: # ble_evt_hardware_adc_result
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
