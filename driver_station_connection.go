// Copyright 2014 Team 254. All Rights Reserved.
// Author: pat@patfairbank.com (Patrick Fairbank)
//
// Model and methods for interacting with a team's Driver Station.

package main

import (
	"fmt"
        "log"
	"net"
	"strings"
	"time"
)

// UDP port numbers that the Driver Station sends and receives on.
const driverStationSendPort = 1120
const driverStationReceivePort = 1160
const driverStationProtocolVersion = "11191100"
const driverStationLinkTimeoutMs = 500
const competitionName = "TEST"
const fmsVersion = "2015 Update 6.1.6.8"
const rioVersion = "FRC_roboRIO_2015_v18"
const dsVersion = "09121400"
const inquiry = "Coolest robot EVER!!??"

var inquiryValue = 1000

type DriverStationStatus struct {
	TeamId            int
	AllianceStation   string
	DsLinked          bool
	RobotLinked       bool
	Auto              bool
	Enabled           bool
	EmergencyStop     bool
	BatteryVoltage    float64
	DsVersion         string
	PacketCount       int
	MissedPacketCount int
	DsRobotTripTimeMs int
	MBpsToRobot       float64
	MBpsFromRobot     float64
}

type DriverStationConnection struct {
	TeamId                    int
	AllianceStation           string
	Auto                      bool
	Enabled                   bool
	EmergencyStop             bool
	DriverStationStatus       *DriverStationStatus
	LastPacketTime            time.Time
	LastRobotLinkedTime       time.Time
	SecondsSinceLastRobotLink float64
	conn                      net.Conn
	packetCount               int
	missedPacketOffset        int
	log                       *TeamMatchLog
}

var teamList map[int]*DriverStationConnection

// Opens a UDP connection for communicating to the driver station.
func NewDriverStationConnection(teamId int, station string) (*DriverStationConnection, error) {
        if (nil == teamList) {
            teamList = make(map[int]*DriverStationConnection)
        }
        teamList[teamId] = &DriverStationConnection{TeamId: teamId, AllianceStation: station,
		DriverStationStatus: new(DriverStationStatus), conn: nil}
        return teamList[teamId], nil

}

// Sends a control packet to the Driver Station and checks for timeout conditions.
func (dsConn *DriverStationConnection) Update() error {
        if (nil == dsConn.conn) {
            return nil
        }

	err := dsConn.sendControlPacket()
	if err != nil {
		return err
	}

	if time.Since(dsConn.LastPacketTime).Seconds()*1000 > driverStationLinkTimeoutMs {
		dsConn.DriverStationStatus.DsLinked = false
		dsConn.DriverStationStatus.RobotLinked = false
		dsConn.DriverStationStatus.BatteryVoltage = 0
		dsConn.DriverStationStatus.MBpsToRobot = 0
		dsConn.DriverStationStatus.MBpsFromRobot = 0
	}

	return nil
}

func (dsConn *DriverStationConnection) Close() error {
	if dsConn.log != nil {
		dsConn.log.Close()
	}
        if (nil == dsConn.conn) {
            return nil
        }
	return dsConn.conn.Close()
}

// Sets up a watch on the UDP port that Driver Stations send on.
func DsPacketListener() (*net.UDPConn, error) {
	udpAddress, err := net.ResolveUDPAddr("udp4", fmt.Sprintf(":%d", driverStationReceivePort))
	if err != nil {
		return nil, err
	}
	listen, err := net.ListenUDP("udp4", udpAddress)
	if err != nil {
		return nil, err
	}
	return listen, nil
}

// Loops indefinitely to read packets and update connection status.
func ListenForDsPackets(listener *net.UDPConn) {
	var data [50]byte
	for {
		rsz, _ := listener.Read(data[:])
		dsStatus := decodeStatusPacket(data, rsz)

		// Update the status and last packet times for this alliance/team in the global struct.
		dsConn := mainArena.AllianceStations[dsStatus.AllianceStation].DsConn
		if dsConn != nil && dsConn.TeamId == dsStatus.TeamId {
			dsConn.DriverStationStatus = dsStatus
			dsConn.LastPacketTime = time.Now()
			if dsStatus.RobotLinked {
				dsConn.LastRobotLinkedTime = time.Now()
			}
			dsConn.SecondsSinceLastRobotLink = time.Since(dsConn.LastRobotLinkedTime).Seconds()
			dsConn.DriverStationStatus.MissedPacketCount -= dsConn.missedPacketOffset

			// Log the packet if the match is in progress.
			matchTimeSec := mainArena.MatchTimeSec()
			if matchTimeSec > 0 && dsConn.log != nil {
				dsConn.log.LogDsStatus(matchTimeSec, dsStatus)
			}
		}
	}
}

// Sets up a watch on the TCP port that Driver Stations send on.
func DsIpListener() (*net.TCPListener, error) {
    tcpAddress, err := net.ResolveTCPAddr("tcp4", "10.0.100.5:1750")
    if err != nil {
            return nil, err
    }
    listen, err := net.ListenTCP("tcp4", tcpAddress)
    if err != nil {
            return nil, err
    }
    return listen, nil
}

func DsIpConfig(socket *net.TCPConn) {
    var header [3]byte
    var dsc *DriverStationConnection
    var inqVal int
    done := false
    team := int(0)
    for !done {
        var msg [65535]byte
        cnt, err := socket.Read(header[:])
        if (nil != err || 0 == cnt) {
            break
        }
        mlen := int(header[0]) * 256 + int(header[1])
        pktype := header[2]
        if (false && 0x1c != pktype) {
            log.Printf("team %d message id %x len %d", team, pktype, mlen)
        }
        switch pktype {
        case 0x02:                      // ds version
            socket.Read(msg[:mlen-1])

        case 0x1b:                      // inquiry response
            socket.Read(msg[:mlen-1])
            // done = true
            addr := strings.Split(socket.RemoteAddr().String(), ":")
            conn, err := net.Dial("udp4", fmt.Sprintf("%s:%d", addr[0], driverStationSendPort))
            if err != nil {
                log.Printf("team %d udp connect error, %s", team, err)
                continue
            }
            log.Printf("team %d udp connect at %s:%d", team, addr[0], driverStationSendPort);
            dsc.conn = conn
            dsc.sendControlPacket()
        case 0x1c, 0x16, 0x17:                      // (1c) ds ping  (16) logdata (17) error/event data
            socket.Read(msg[:mlen-1])
        case 0x18:                      // ds team number
            socket.Read(msg[:mlen-1])
            team = int(msg[0]) * 256 + int(msg[1])
            dsc = teamList[team]
            if (nil == dsc) {
                log.Printf("team %d is not a configured team", team)
                mlen = 0
                msg[mlen] = 0        ; mlen++
                msg[mlen] = 3        ; mlen++
                msg[mlen] = 0x19     ; mlen++     // ds team number reply
                msg[mlen] = 0        ; mlen++     // no station
                msg[mlen] = 2        ; mlen++     // not configured
                socket.Write(msg[:mlen])
                continue
            }
            var sta byte
            sta = (dsc.AllianceStation[1] - 0x31)
            if ('B' == dsc.AllianceStation[0]) {
                sta += 3
            }
            mlen = 0
            msg[mlen] = 0        ; mlen++
            msg[mlen] = 3        ; mlen++
            msg[mlen] = 0x19     ; mlen++     // ds team number reply
            msg[mlen] = sta      ; mlen++     // station number  r=0,1,2  b=3,4,5
            msg[mlen] = 0        ; mlen++     // 0 good
            socket.Write(msg[:mlen])

            mlen= 0
            msg[mlen] = 0        ; mlen++
            msg[mlen] = byte(2 + len(competitionName))  ; mlen++
            msg[mlen] = 0x14     ; mlen++               // Event Code
            msg[mlen] = byte(len(competitionName))      ; mlen++
            for i := 0; i < len(competitionName); i++ {
                msg[mlen] = competitionName[i]   ; mlen++
            }
            socket.Write(msg[:mlen])

            mlen= 0
            msg[mlen] = 0        ; mlen++
            msg[mlen] = byte(2 + len(fmsVersion))      ; mlen++
            msg[mlen] = 0x00     ; mlen++              // fms version
            msg[mlen] = byte(len(fmsVersion))          ; mlen++
            for i := 0; i < len(fmsVersion); i++ {
                msg[mlen] = fmsVersion[i]        ; mlen++
            }
            msg[mlen] = 0        ; mlen++
            msg[mlen] = byte(2 + len(rioVersion))      ; mlen++
            msg[mlen] = 0x01     ; mlen++              // rio version
            msg[mlen] = byte(len(rioVersion))          ; mlen++
            for i := 0; i < len(rioVersion); i++ {
                msg[mlen] = rioVersion[i]        ; mlen++
            }
            msg[mlen] = 0        ; mlen++
            msg[mlen] = byte(2 + len(dsVersion))       ; mlen++
            msg[mlen] = 0x02     ; mlen++              // ds? version
            msg[mlen] = byte(len(dsVersion))           ; mlen++
            for i := 0; i < len(dsVersion); i++ {
                msg[mlen] = dsVersion[i]         ; mlen++
            }
            socket.Write(msg[:mlen])

            mlen= 0
            msg[mlen] = 0        ; mlen++
            msg[mlen] = byte(4 + len(inquiry))         ; mlen++
            msg[mlen] = 0x1a     ; mlen++              // inquiry
            msg[mlen] = byte(len(inquiry))             ; mlen++
            for i := 0; i < len(inquiry); i++ {
                msg[mlen] = inquiry[i]           ; mlen++ 
            }

            inqVal = inquiryValue
            inquiryValue = inquiryValue + 1
            msg[mlen] = byte(inqVal / 256)    ; mlen++
            msg[mlen] = byte(inqVal % 256)    ; mlen++
            socket.Write(msg[:mlen])

        default:
            log.Printf("team %d unknown message id %x recieved len %d", team, pktype, mlen)
            socket.Read(msg[:mlen-1])
        }
    }
    socket.Close()
}

// Loops indefinitely to read driver station announced ip-address
func ListenForDsIp(listener *net.TCPListener) {
    for {
        conn, err := listener.AcceptTCP()
        if err != nil {
            log.Printf("Unable to accept socket from DS IP Listener")
            continue
        }
        go DsIpConfig(conn)
    }
}

// Called at the start of the match to allow for driver station initialization.
func (dsConn *DriverStationConnection) signalMatchStart(match *Match) error {
	// Zero out missed packet count and begin logging.
	dsConn.missedPacketOffset = dsConn.DriverStationStatus.MissedPacketCount
	var err error
	dsConn.log, err = NewTeamMatchLog(dsConn.TeamId, match)
	return err
}

// Serializes the control information into a packet.
func (dsConn *DriverStationConnection) encodeControlPacket() [22]byte {
	var packet [22]byte

	// Packet number, stored big-endian in two bytes.
	packet[0] = byte((dsConn.packetCount >> 8) & 0xff)
	packet[1] = byte(dsConn.packetCount & 0xff)

        // comm version
	packet[2] = 0x00

        // 0x2 == auto, 0x4 == enabled, 0x80 == estop
	packet[3] = 0x00
	if dsConn.Auto {
		packet[3] |= 0x02
	}
	if dsConn.Enabled {
		packet[3] |= 0x04
	}
	if dsConn.EmergencyStop {
		packet[3] |= 0x80
	}

        // request
	packet[4] = 0x0

	// Alliance station, 0-2 red, 3-5 blue
        packet[5] = (dsConn.AllianceStation[1] - 0x31)
        if ('B' == dsConn.AllianceStation[0]) {
            packet[5] += 3
        }

        // tourney level
        packet[6] = 0x0

        // match number
        packet[7] = 0x0
        packet[8] = 0x1

        // play number
        packet[9] = 0x0

        currentTime := time.Now()

        currMs := currentTime.Nanosecond()

        // field time ms
        packet[10 + 0] = byte(0xff & (currMs >> 24))
        packet[10 + 1] = byte(0xff & (currMs >> 16))
        packet[10 + 2] = byte(0xff & (currMs >> 8))
        packet[10 + 3] = byte(0xff & currMs )

        // field time : ss min hr dy mon (yr - 1900))
        packet[14] = byte(0xff & currentTime.Second())
        packet[15] = byte(0xff & currentTime.Minute())
        packet[16] = byte(0xff & currentTime.Hour())
        packet[17] = byte(0xff & currentTime.Day())
        packet[18] = byte(0xff & currentTime.Month())
        packet[19] = byte(0xff & (currentTime.Year() - 1900))

        // remaining match time
        matchTime := int(mainArena.MatchTimeSec())
        packet[20] = byte(0xff & (matchTime >> 8))
        packet[21] = byte(0xff & matchTime)

	// Increment the packet count for next time.
	dsConn.packetCount++

	return packet
}

// Builds and sends the next control packet to the Driver Station.
func (dsConn *DriverStationConnection) sendControlPacket() error {
	packet := dsConn.encodeControlPacket()
	_, err := dsConn.conn.Write(packet[:])
	if err != nil {
		return err
	}

	return nil
}

// Deserializes a packet from the DS into a structure representing the DS/robot status.
func decodeStatusPacket(data [50]byte, pktsize int) *DriverStationStatus {
        var dsc *DriverStationConnection
	dsStatus := new(DriverStationStatus)
	dsStatus.DsLinked = true

        // data[2]  comm version (00)

	// Robot status byte.
        // 0x2 == auto, 0x4 == enabled, 0x8 == rio, 0x10 == radio, 0x20 == robot, 0x80 == estop
	dsStatus.RobotLinked = (data[3] & 0x20) != 0
	dsStatus.Auto = (data[3] & 0x02) != 0
	dsStatus.Enabled = (data[3] & 0x04) != 0
	dsStatus.EmergencyStop = (data[3] & 0x80) == 0

	// Team number, stored in two bytes as hundreds and then ones (like the IP address).
	dsStatus.TeamId = int(data[4])*256 + int(data[5])
        dsc = teamList[dsStatus.TeamId]

	// Robot battery voltage
	dsStatus.BatteryVoltage = float64(data[6]) + ( float64( data[7] ) / 256.0 )

	// Alliance station, stored as ASCII characters 'R/B' and '1/2/3'.
	dsStatus.AllianceStation = dsc.AllianceStation

	// Driver Station software version, stored as 8-byte string.
	// dsStatus.DsVersion = string(data[18:26])

        if (8 < pktsize) {
            for rsize := 8 ; pktsize > rsize ; {
                if (2 > pktsize - rsize) {
                    break
                }
                esize := data[rsize]
                switch (data[1 + rsize]) {
                case 0x0:       // Field Radio
                    // sig strength = data[2 + rsize]
                    // bandwith util = data[3 + rsize]
                    ;
                case 0x1:       // Comm metrics
                    // Number of missed packets sent from the DS to the robot, stored in two big-endian bytes.
                    dsStatus.MissedPacketCount = int(data[2 + rsize])*256 + int(data[3 + rsize])

                    // Total number of packets sent from the DS to the robot, stored in two big-endian bytes.
                    dsStatus.PacketCount = int(data[4 + rsize])*256 + int(data[5 + rsize])
                    // log.Printf("team %d comm miss %4d packet %4d", dsStatus.TeamId, dsStatus.MissedPacketCount, dsStatus.PacketCount );

                case 0x2:       // laptop info
                    // battery pct
                    // dsStatus.BatteryVoltage = float64(data[2 + rsize]) / 12.0
                    // cpu pct
                    //  data[3 + rsize]
                    // log.Printf("team %d laptop batt %4d cpu %4d", dsStatus.TeamId, data[2 + rsize], data[3 + rsize]);

                // case 0x3: 
                // case 0x4:
                default:
                    log.Printf("unknown extension tag %x len %d", data[1 + rsize], esize)
                }

                rsize = rsize + int(esize) + 1
            }
        }

	// Average DS-robot trip time in milliseconds, stored in two big-endian bytes.
	// dsStatus.DsRobotTripTimeMs = int(data[30])*256 + int(data[31])

	return dsStatus
}
