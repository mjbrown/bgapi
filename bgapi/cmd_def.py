class ReturnCodeLookupDict(object):
   """A return code lookup dict that returns a default placeholder string if requested code is not present in the original table."""

   def __init__(self, lookup):
      self._lookup = lookup

   def __getitem__(self, code):
      try:
         rv = self._lookup.get(code)
      except KeyError:
         rv = "Unknown Code 0x%02X"
      return rv

   def get(self, code, default=None):
      return self._lookup.get(code, default)

RESULT_CODE = ReturnCodeLookupDict({
   0x0000: "OK",
   0x0180: "Invalid Parameter",
   0x0181: "Device in Wrong State",
   0x0182: "Out Of Memory",
   0x0183: "Feature Not Implemented",
   0x0184: "Command Not Recognized",
   0x0185: "Timeout",
   0x0186: "Not Connected",
   0x0187: "Flow",
   0x0188: "User Attribute",
   0x0189: "Invalid License Key",
   0x018A: "Command Too Long",
   0x018B: "Out of Bounds",
   0x0205: "Authentication Failure",
   0x0206: "Pin Or Key Missing",
   0x0207: "Memory Capacity Exceeded",
   0x0208: "Connection Timeout",
   0x0209: "Connection Limit Exceeded",
   0x020C: "Command Disallowed",
   0x0212: "Invalid Command Parameters",
   0x0213: "Remote User Terminated Connection",
   0x0216: "Connection Terminated by Local Host",
   0x0222: "Link Layer Timeout",
   0x0228: "Link Layer Instant Passed",
   0x023A: "Controller Busy",
   0x023B: "Unacceptable Connection Interval",
   0x023C: "Directed Advertising Timeout",
   0x023D: "Message Integrity Check Failure",
   0x023E: "Connection Failed to be Established",
   0x0301: "Passkey Entry Failed",
   0x0302: "Out of Band Data is Not Available",
   0x0303: "Authentication Requirements",
   0x0304: "Confirm Value Failed",
   0x0305: "Pairing Not Supported",
   0x0306: "Encryption Key Size",
   0x0307: "Command Not Supported",
   0x0308: "Unspecified Pairing Failure",
   0x0309: "Repeated Attempts",
   0x030A: "Invalid Parameters",
   0x0401: "Invalid Handle",
   0x0402: "Read Not Permitted",
   0x0403: "Write Not Permitted",
   0x0404: "Invalid PDU",
   0x0405: "Insufficient Authentication",
   0x0406: "Request Not Supported",
   0x0407: "Invalid Offset",
   0x0408: "Insufficient Authorization",
   0x0409: "Prepare Queue Full",
   0x040A: "Attribute Not Found",
   0x040B: "Attribute Not Long",
   0x040C: "Insufficient Encryption Key Size",
   0x040D: "Invalid Attribute Value Length",
   0x040E: "Unlikely Error",
   0x040F: "Insufficient Encryption",
   0x0410: "Unsupported Group Type",
   0x0411: "Insufficient Resources",
   0x0480: "Application Error Codes",
   })


ATTRIBUTE_CHANGE_REASON = ReturnCodeLookupDict({
   0x0: "Write Request",
   0x1: "Write Command",
   0x2: "Write Request User"
   })

ATTRIBUTE_STATUS_FLAGS = ReturnCodeLookupDict({
   0x0: "NoNotifications or Indications",
   0x1: "Notification",
   0x2: "Indication",
   0x3: "Notification and Indication"
   })

ATTRIBUTE_VALUE_TYPE = ReturnCodeLookupDict({
   0x0: "Read",
   0x1: "Notification",
   0x2: "Indication",
   0x3: "Read By Type",
   0x4: "Read Blob",
   0x5: "Indication Response Requested"
   })

system_endpoints= {
	'system_endpoint_api': 0,
	'system_endpoint_test': 1,
	'system_endpoint_script': 2,
	'system_endpoint_usb': 3,
	'system_endpoint_uart0': 4,
	'system_endpoint_uart1': 5,
	'system_endpoints_max': 6
}

connection_status_mask= {
	'connection_connected': 1,
	'connection_encrypted': 2,
	'connection_completed': 4,
	'connection_parameters_change': 8,
}

sm_bonding_key= {
	'sm_bonding_key_ltk': 0x01,
	'sm_bonding_key_addr_public': 0x02,
	'sm_bonding_key_addr_static': 0x04,
	'sm_bonding_key_irk': 0x08,
	'sm_bonding_key_edivrand': 0x10,
	'sm_bonding_key_csrk': 0x20,
	'sm_bonding_key_masterid': 0x40,
	'sm_bonding_key_max': 65
}

sm_io_capability= {
	'sm_io_capability_displayonly': 0,
	'sm_io_capability_displayyesno': 1,
	'sm_io_capability_keyboardonly': 2,
	'sm_io_capability_noinputnooutput': 3,
	'sm_io_capability_keyboarddisplay': 4,
	'sm_io_capability_max': 5
}

globaldefs = {}
globaldefs['GAP_SCAN_HEADER_ADV_IND'] = 0
globaldefs['GAP_SCAN_HEADER_ADV_DIRECT_IND'] = 1
globaldefs['GAP_SCAN_HEADER_ADV_NONCONN_IND'] = 2
globaldefs['GAP_SCAN_HEADER_SCAN_REQ'] = 3
globaldefs['GAP_SCAN_HEADER_SCAN_RSP'] = 4
globaldefs['GAP_SCAN_HEADER_CONNECT_REQ'] = 5
globaldefs['GAP_SCAN_HEADER_ADV_DISCOVER_IND'] = 6

globaldefs['GAP_AD_FLAG_LIMITED_DISCOVERABLE'] = 0x01
globaldefs['GAP_AD_FLAG_GENERAL_DISCOVERABLE'] = 0x02
globaldefs['GAP_AD_FLAG_BREDR_NOT_SUPPORTED'] = 0x04
globaldefs['GAP_AD_FLAG_SIMULTANEOUS_LEBREDR_CTRL'] = 0x10
globaldefs['GAP_AD_FLAG_SIMULTANEOUS_LEBREDR_HOST'] = 0x20
globaldefs['GAP_AD_FLAG_MASK'] = 0x1f


gap_address_type= {
	'gap_address_type_public': 0,
	'gap_address_type_random': 1,
	'gap_address_type_max': 2
}

gap_discoverable_mode= {
	'gap_non_discoverable': 0,
	'gap_limited_discoverable': 1,
	'gap_general_discoverable': 2,
	'gap_broadcast': 3,
	'gap_user_data': 4,
	'gap_discoverable_mode_max': 5
}

gap_connectable_mode= {
	'gap_non_connectable': 0,
	'gap_directed_connectable': 1,
	'gap_undirected_connectable': 2,
	'gap_scannable_connectable': 3,
	'gap_connectable_mode_max': 4
}

gap_discover_mode= {
	'gap_discover_limited': 0,
	'gap_discover_generic': 1,
	'gap_discover_observation': 2,
	'gap_discover_mode_max': 3
}

gap_ad_types= {
	'gap_ad_type_none': 0,
	'gap_ad_type_flags': 1,
	'gap_ad_type_services_16bit_more': 2,
	'gap_ad_type_services_16bit_all': 3,
	'gap_ad_type_services_32bit_more': 4,
	'gap_ad_type_services_32bit_all': 5,
	'gap_ad_type_services_128bit_more': 6,
	'gap_ad_type_services_128bit_all': 7,
	'gap_ad_type_localname_short': 8,
	'gap_ad_type_localname_complete': 9,
	'gap_ad_type_txpower': 10,
	'gap_ad_types_max': 11
}

gap_advertising_policy= {
	'gap_adv_policy_all': 0,
	'gap_adv_policy_whitelist_scan': 1,
	'gap_adv_policy_whitelist_connect': 2,
	'gap_adv_policy_whitelist_all': 3,
	'gap_advertising_policy_max': 4
}

gap_scan_policy= {
	'gap_scan_policy_all': 0,
	'gap_scan_policy_whitelist': 1,
	'gap_scan_policy_max': 2
}
