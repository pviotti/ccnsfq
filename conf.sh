#!/bin/bash

DEV="eth0"
BW="10mbit"

function usage(){
	echo "Usage: $0 {mkmod|add|show|ker|del|rmmod}."
	echo ""
	echo "	mkmod: build and insert the ccnsfq module"
	echo "	add: shape to $BW and add the ccnsfq queuing discipline to $DEV"
	echo "	show: show qdisc statistics"
	echo "	ker: show kernel log messages"
	echo "	del: remove shaping and the ccnsfq queuing discipline from $DEV"
	echo "	rmmod: remove the ccnsfq module and clean"
	echo ""
}

if [ $# != 1 ]
then
	echo "Error: not enough arguments."
	usage
	exit 1
fi

case $1 in
	mkmod)	echo "Building and inserting ccnsfq module..."
			make && sudo insmod ./sch_ccnsfq.ko
			;;
	
	rmmod)	echo "Removing ccnsfq module and cleaning..."
			sudo rmmod ./sch_ccnsfq.ko
			make clean
			;;
	

	add)	#echo "Shaping $DEV to $BW..."
			#sudo tc qdisc add dev $DEV root handle 1: tbf rate $BW burst 100kb latency 30ms peakrate 12mbit minburst 1540
			echo "Adding ccnsfq to $DEV..."
			#sudo tc qdisc add dev $DEV parent 1:0 handle 2:10 ccnsfq
			sudo tc qdisc add dev eth0 root handle 1: ccnsfq limit 30
			;;

	del)	echo "Removing ccnsfq and shaping from $DEV..."
			sudo tc qdisc del dev $DEV root
			;; 

	show)	echo "Showing qdisc details..."
			tc -s -d qdisc show 	# -s = statistics; -d = details
									# tc qdisc show dev $DEV
			;;

	ker)	echo "Showing kernel log messages..."
			tail -f /var/log/messages # -f: continuous monitoring
			;;	

	*)	echo "Error: argument not recognized."
		usage
		exit 1
		;;
esac
