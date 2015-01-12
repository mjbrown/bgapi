import time
import sys
import logging
import logging.handlers

from bgmodule import BlueGigaModule, GATTCharacteristic, GATTService
from cmd_def import gap_discoverable_mode, gap_connectable_mode

CLIENT_SERIAL = "COM9"
SERVER_SERIAL = "COM11"

term = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
term.setFormatter(formatter)
api_logger = logging.getLogger("bgapi")
api_logger.addHandler(term)
api_logger.setLevel(level=logging.INFO)

def example_physical_web():
    ble_client = BlueGigaModule(port=CLIENT_SERIAL, timeout=0.1)
    ble_server = BlueGigaModule(port=SERVER_SERIAL, timeout=0.1)

    ble_client.reset_ble_state()
    ble_server.reset_ble_state()

    ble_server.setup_physical_web("http://www.bluegiga.com")
    ble_server.start_advertisement(adv_mode=gap_discoverable_mode['gap_user_data'],
                                   conn_mode=gap_connectable_mode['gap_undirected_connectable'])
    responses = ble_client.scan_all(timeout=3)

def example_ibeacon():
    ble_client = BlueGigaModule(port=CLIENT_SERIAL, timeout=0.1)
    ble_server = BlueGigaModule(port=SERVER_SERIAL, timeout=0.1)

    ble_server.reset_ble_state()
    ble_client.reset_ble_state()

    ble_server.setup_ibeacon(uuid="e2c56db5-dffb-48d2-b060-d0f5a71096e0",
                                 major=0, minor=0)
    ble_server.start_advertisement(adv_mode=gap_discoverable_mode['gap_user_data'],
                                   conn_mode=gap_connectable_mode['gap_undirected_connectable'])
    responses = ble_client.scan_all(timeout=3)

def example_simultaneous_beacons():
    ble_client = BlueGigaModule(port=CLIENT_SERIAL, timeout=0.1)
    ble_server = BlueGigaModule(port=SERVER_SERIAL, timeout=0.1)

    ble_server.reset_ble_state()
    ble_client.reset_ble_state()

    ble_server.setup_ibeacon(uuid="e2c56db5-dffb-48d2-b060-d0f5a71096e0",
                                 major=0, minor=0)
    ble_server.start_advertisement(adv_mode=gap_discoverable_mode['gap_user_data'],
                                   conn_mode=gap_connectable_mode['gap_undirected_connectable'])
    for i in range(30):
        time.sleep(1)
        ble_server.setup_physical_web("http://www.bluegiga.com")
        time.sleep(1)
        ble_server.setup_ibeacon(uuid="e2c56db5-dffb-48d2-b060-d0f5a71096e0",
                                 major=0, minor=0)

def example_client_operations():
    ble_client = BlueGigaModule(port=CLIENT_SERIAL, timeout=0.1)
    ble_server = BlueGigaModule(port=SERVER_SERIAL, timeout=0.1)

    # BLE Device configuration and start advertising
    ble_server.reset_ble_state()
    ble_server.get_module_info()
    ble_server.set_device_capabilities()
    ble_server.delete_bonding()
    ble_server.allow_bonding()
    ble_server.advertise_general()

    # BLE Client configuration and start scanning
    ble_client.get_module_info()
    ble_client.reset_ble_state()
    ble_client.delete_bonding()
    ble_client.allow_bonding()
    responses = ble_client.scan_all(timeout=3)
    for resp in responses:
        if resp.get_sender_address() == ble_server.get_ble_address():
            target = resp
            break
    else:
        raise Exception("No Advertisements received from server %s" % (ble_server.get_ble_address()))
    connection = ble_client.connect(target=target)
    oob_data = "000102030405060708090A0B0C0D0E0F"
    ble_client.set_out_of_band_data(oob_data)
    ble_server.set_out_of_band_data(oob_data)
    ble_client.request_encryption(connection, bond=True)
    ble_client.read_by_group_type(connection, type=GATTService.PRIMARY_SERVICE_UUID)
    ble_client.read_by_group_type(connection, type=GATTService.SECONDARY_SERVICE_UUID)
    for service in ble_client.get_services(connection):
        ble_client.find_information(connection=connection, service=service)
        ble_client.read_by_type(connection=connection, service=service, type=GATTCharacteristic.CHARACTERISTIC_UUID)
        ble_client.read_by_type(connection=connection, service=service, type=GATTCharacteristic.CLIENT_CHARACTERISTIC_CONFIG)

    for characteristic in ble_client.connections[connection].get_characteristics():
        ble_client.read_by_handle(connection, characteristic.value_handle)

    ble_client.disconnect(connection)
    time.sleep(1)  # So that we can see the server disconnect event

if __name__ == "__main__":
    example_client_operations()
    #example_ibeacon()
    #example_physical_web()
    #example_simultaneous_beacons()