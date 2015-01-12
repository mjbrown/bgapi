bgapi_py
==================
A library for using Bluetooth Low Energy modules created by BlueGiga, based upon preliminary work https://github.com/jrowberg/bglib.
However, the goal of that implementation is to look as similar as possible to the C library provided by BlueGiga.  The primary
goal of this library is to leverage polymorphism and the capabilities of modern IDEs like PyCharm.
Examples are provided for both client and server functionality.  Note that if you want to develop your own device profile,
it requires a module firmware update.

bgapi.py has two important components:

1. BlueGigaAPI wraps the serial connection, it can be used synchronously by calling the polling function,
   or it can be used asynchronously by starting the daemon thread.

2. BlueGigaCallbacks is a base class for callbacks from responses and events received from the module.  Inherit
   this class and override the functions you need to trigger your code or get your data.

cmd_def.py eliminates the need for magic numbers in method parameters, use it for more readable code.

bgmodule.py wraps the API in an additional layer of abstraction.  It attempts to
 eliminate the need to understand the BlueGiga API whatsoever.
 
Example Code
====================
The test folder demonstrates high level Bluetooth Smart operations.  It provides examples of Apple's iBeacon and
Google's prototype Physical Web.  Testing of this library is limited to what you see in these examples.  Many BGAPI
commands cannot be tested, especially hardware operations like GPIO and I2C.  Two BLE112 devices are needed for all tests.

In Progress
====================
1. Test code for authentication, encryption, and bonding.

2. Test code for attribute transactions.

3. Adjust ble_cmd functions for ease of use (data types and endianess).