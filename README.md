The **ccnsfq scheduler** is a qdisc-like Linux packet scheduler that adapts the characteristics of the [SFQ (Stochastic Fair Queueing) scheduler][1] in order to provide [CCNx][2] flow isolation.  
In this context, a CCNx flow is identified by the CCNx name (including the file version) written on the CCNx header, and the type of CCNx packet (i.e. *Interest* or *Data*).  

This packet scheduler was developed in _2010_, as a collateral effort for my M.Sc. thesis in computers and communication networks at [PoliTo][3] and [Telecom ParisTech][4], during a six months intership at [Orange Labs][5].  

For the performance results obtained using this scheduler, please refer to [my M.Sc. thesis][6].


[1]: http://lxr.linux.no/#linux+v2.6.32.61/net/sched/sch_sfq.c
[2]: http://www.ccnx.org/
[3]: http://www.polito.it/
[4]: http://www.telecom-paristech.fr
[5]: http://www.orange.com/en/innovation/research
[6]: http://perso.rd.francetelecom.fr/muscariello/MS-thesis-viotti.pdf


### Features and requirements

 * tested on Linux 2.6.32 (Ubuntu 10.4, 32bit)
 * works with CCNx over UDP and supports also one level of IP tunneling
 * the binary parsing to extrapolate the CCNx name is performed using the functions provided by the CCNx prototype version 0.2+git04/2010 (they have been included in a self-containing C file named `parser.c` beside the ccnsfq scheduler module itself)
 * all the non-CCNx packets are queued in a single separate queue

The *ccnsfq_hash* function computes hash digests that are used to distinguish different CCNx flows.  
All the functions needed to parse the packets have been taken from the CCNx prototype version 0.2+git04/2010 and included in a self-containing C file named `parser.c` which is referenced by the ccnsfq module.  

A simple add-on in the placed in the `tc_ccnsfq` folder allows the **tc** tool to recognize the new scheduler and print some useful information about it.  

To build and install the kernel module you can use `conf.sh`.


### What does this scheduler provide?

 * work conserving scheduling service
 * per-CCNx flow queuing (flow isolation)
 * max-min fairness (i.e. maximizes the minimum bandwidth allocation)
 * protection against variable frame size unfairness (using a quantum, as in DRR)

It does not provide any flow based prioritization.

### Known bugs
 
It does not correctly handle IP fragmentation of CCNx packets, so the IP fragments are treated as belonging to separate non-CCNx flows. Thus to make it work correctly you should publish files (e.g. using `ccnputfile`) having small chunck size.


### Licence

Copyright 2010 Paolo Viotti <paolo.viotti@gmail.com>.  

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 3
of the License, or (at your option) any later version.  

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.  

For the licensing details see the COPYING file in this repository.

