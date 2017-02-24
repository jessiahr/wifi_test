require 'securerandom'
require 'timeout'
# require 'byebug'
class Probe
  def self.start_mon(ifname = "wlx00c0ca830670")
    puts "starting mon mode"
    monmode_results = `airmon-ng start #{ifname}`
    puts "results: #{monmode_results}"

    #check if the network was put into mon
    if monmode_results.include? "monitor mode enabled on"
      puts "#{ifname} now in mon mode!"
    else
      raise "Network interface: unable to stop"
    end
  end

  def self.stop_mon(ifname = "wlx00c0ca830670")
    puts "stoping mon mode"
    monmode_results = `airmon-ng stop #{ifname}mon`

    puts "results: #{monmode_results}"

    #check if the network was put into mon
    if !monmode_results.include? "wlan0mone"
      puts "SUCCESS"
    else
      raise "Network interface: unable to stop"
    end
  end

  def self.dump
    puts "dumping"
    temp_filename = SecureRandom.hex(10)
    puts "started #{temp_filename}"

    status = Timeout::timeout(10) {
      `timeout 5s airodump-ng mon0  --output-format "csv" -w "./#{temp_filename}" & echo "closing airodump..." & puts "closing scan."`
    } rescue Timeout::Error
puts "Files #{temp_filename}"
    accesspoints = []
    format = []
    File.foreach("#{temp_filename}-01.csv") { |line|
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
     return accesspoints

  end

  def self.read_dump
    File.foreach("example.csv") do |line|
      print "GOT", line, "{[#{line.split.length}]}"
    end
  end
end
# Probe.start_mon
# points = Probe.dump
# Probe.stop_mon
# # Probe.read_dump
# puts points
# puts "%%%"
# points.each do |point|
#   puts "bssid\t#{point['bssid']}\t#{point['essid']}"
# end

class Dump
  def initialize(filename)
    @filename = filename
  end

  def read
    accesspoints = []
    clients = []
    format = []
    parsing_accesspoints = true # reads accesspoints first
    File.foreach("#{@filename}-01.csv") { |line|
      puts line
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
          clients << Hash[format.zip(line.split(','))]
       end
      #  print "--#{line}--"
     }
     {'accesspoints' => accesspoints, 'clients' => clients}
  end

end

class Slappy
  def whitelist
    ['00:c0:ca:83:06:70']
  end

  def disconnect(id)
    `aireplay-ng -0 5  --ignore-negative-one -a 1C:B7:2C:CC:93:70 -c 00:C0:CA:83:06:70 mon0`
  end
end

dump = Dump.new('6acd158bc43227b16c5c')
puts dump.read
