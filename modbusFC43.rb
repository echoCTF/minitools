##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'        => 'Modbus FC43 Scanner',
      'Description' => %q{
          This module performs FC43 operation on a modbus server returning
          extended device informaion. Only tested this on emulated modbus
          environments so not sure about its validity.
      },
      'References'  =>
        [
          [ 'URL', 'http://www.saia-pcd.com/en/products/plc/pcd-overview/Pages/pcd1-m2.aspx' ],
          [ 'URL', 'http://en.wikipedia.org/wiki/Modbus:TCP' ]
        ],
      'Author'      => [ 'Pantelis Roditis <proditis[at]echothrust.com>' ],
      'DisclosureDate' => 'Oct 16 2019',
      'License'     => MSF_LICENSE
      )

    register_options(
      [
        Opt::RPORT(502),
        OptInt.new('UNIT_ID', [true, "ModBus Unit Identifier, 1..255, most often 1 ", 1]),
        OptInt.new('DEVICE_ID', [true, "ModBus Device Id, 1..4, most often 1 ", 1]),
        OptInt.new('OBJECT_ID', [true, "ModBus OBJECT Id, 0..128, most often 0 ", 0]),
        OptInt.new('TIMEOUT', [true, 'Timeout for the network probe', 10])
      ])
  end

  def run_host(ip)
    # Perform FC43/14
    # \x01\x2B\x0E\x01\x00\x06
    # 01 = unitID
    # 2B = FC43
    # 0E = 14
    # 01 = DeviceID
    # 00 = ObjectID
    sploit="\xda\x51\x01\x00\x00\x06\x01\x2B\x0E\x02\x00\x06"

    sploit[6] = [datastore['UNIT_ID']].pack("C")
    sploit[9] = [datastore['DEVICE_ID']].pack("C")
    sploit[10] = [datastore['OBJECT_ID']].pack("C")
    connect()
    sock.put(sploit)
    data = sock.get_once

    # Theory: When sending a modbus request of some sort, the endpoint will return
    # with at least the same transaction-id, and protocol-id
    if data
      if data[0,4] == "\xda\x51\x00\x00"
        print_good("#{ip}:#{rport} - MODBUS - received correct MODBUS/TCP header #{data[16,1024].inspect}")
      else
        print_error("#{ip}:#{rport} - MODBUS - received incorrect data #{data[0,4].inspect} (not modbus/tcp?)")
      end
    else
      vprint_status("#{ip}:#{rport} - MODBUS - did not receive data.")
    end

    disconnect()
  end
end
