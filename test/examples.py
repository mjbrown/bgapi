import logging
import time
from bgapi.module import BlueGigaServer
from bgapi.cmd_def import gap_discoverable_mode, gap_connectable_mode

PORT = "COM3"
# PORT = "/dev/ttyACM0"


def example_custom_adv():
    ble_server = BlueGigaServer(port=PORT, baud=115200, timeout=0.1)
    ble_server.reset_ble_state()
    ble_server.pipe_logs_to_terminal(level=logging.DEBUG)
    time.sleep(0.1)     # Give it a moment to reset state
    flags = "\x02\x01\x06" # Flags indicate BLE only
    name = "Complete Device Name"
    adv = flags + chr(len(name)) + "\x09" + name        # 0x09 specifies complete device name
    ble_server._api.ble_cmd_gap_set_adv_data(0, adv_data=adv)
    ble_server.start_advertisement(adv_mode=gap_discoverable_mode['gap_user_data'],
                               conn_mode=gap_connectable_mode['gap_undirected_connectable'])


if __name__ == "__main__":
    example_custom_adv()
    time.sleep(0.1)  # Give it a moment for the responses to come back and get logged

