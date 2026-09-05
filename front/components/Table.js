import * as React from 'react'
import { styled } from '@mui/material/styles'
import Table from '@mui/material/Table'
import TableBody from '@mui/material/TableBody'
import TableCell, { tableCellClasses } from '@mui/material/TableCell'
import TableContainer from '@mui/material/TableContainer'
import TableHead from '@mui/material/TableHead'
import TableRow from '@mui/material/TableRow'
import Paper from '@mui/material/Paper'
import { Button } from '@mui/material'

const StyledTableCell = styled(TableCell)(({ theme }) => ({
  [`&.${tableCellClasses.head}`]: {
    backgroundColor: '#1976d2',
    color: theme.palette.common.white,
  },
  [`&.${tableCellClasses.body}`]: {
    fontSize: 14,
  },
}))

const StyledTableRow = styled(TableRow)(({ theme }) => ({
  '&:nth-of-type(odd)': {
    backgroundColor: theme.palette.action.hover,
  },
  // hide last border
  '&:last-child td, &:last-child th': {
    border: 0,
  },
}))



const rows = [
  {
    title: 'Report 1',
    description:
      `This is a %sample_x_y text
      and this is a Tsample_x_y text
      with multiple manasamplety lines
      in a sample of a JSON object`,
  },
  {
    title: 'Report 2',
    description:
      `            
      Booting...
      
      
      @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
      
      @
      
      @ chip__no chip__id mfr___id dev___id cap___id size_sft dev_size chipSize
      
      @ 0000000h 0c22016h 00000c2h 0000020h 0000016h 0000000h 0000016h 0400000h
      
      @ blk_size blk__cnt sec_size sec__cnt pageSize page_cnt chip_clk chipName
      
      @ 0010000h 0000040h 0001000h 0000400h 0000100h 0000010h 000002ah MX25L3205D
      
      @ 
      
      @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
      
       
      
      ---RealTek(RTL8196E)at 2021.08.03-17:27+0300 v1.3 [16bit](400MHz)
      
      
      gcc: 4.4.5-1.5.5p2 for arch: 4181
      
      hash: 8383eb806e05602eab0af5ac51989af0de8e0767
      
      rep: git+ssh://git@rd/sdk_boot/rtl/boot_3463
      
      
      check_image_header  return_addr:05010000 bank_offset:00000000
      
      no sys signature at 00010000!
      
      no sys signature at 00020000!
      
      ret=2  sys signature at 00030000!
      
      Header -&gt; startAddr:0x80500000, len:3964754
      
      magic at 0x003f7f73
      
      load with header to:0x804ffff0, len:3964790, first_word:63723662
      
      ---
      
      Check dlink signature
      
      ---
      
      Validate OK
      
      ---
      
      Jump to image start=0x80500000...
      
      decompressing kernel:
      Uncompressing Linux... done, booting the kernel.
      done decompressing kernel.
      start address: 0x800034b0
      CPU revision is: 0000cd01
      Determined physical RAM map:
       memory: 02000000 @ 00000000 (usable)
      Zone PFN ranges:
        Normal   0x00000000 -&gt; 0x00002000
      Movable zone start PFN for each node
      early_node_map[1] active PFN ranges
          0: 0x00000000 -&gt; 0x00002000
      Built 1 zonelists in Zone order, mobility grouping on.  Total pages: 8128
      Kernel command line: console=ttyS0,38400 root=31:04 init=/sbin/init
      icache: 16kB/16B, dcache: 8kB/16B, scache: 0kB/0B
      NR_IRQS:48
      PID hash table entries: 128 (order: 7, 512 bytes)
      console handover: boot [early0] -&gt; real [ttyS0]
      Dentry cache hash table entries: 4096 (order: 2, 16384 bytes)
      Inode-cache hash table entries: 2048 (order: 1, 8192 bytes)
      Memory: 23912k/32768k available (3529k kernel code, 8856k reserved, 843k data, 120k init, 0k highmem)
      Calibrating delay loop... 398.95 BogoMIPS (lpj=1994752)
      Mount-cache hash table entries: 512
      net_namespace: 784 bytes
      NET: Registered protocol family 16
      bio: create slab &lt;bio-0&gt; at 0
      NET: Registered protocol family 2
      IP route cache hash table entries: 1024 (order: 0, 4096 bytes)
      TCP established hash table entries: 1024 (order: 1, 8192 bytes)
      TCP bind hash table entries: 1024 (order: 0, 4096 bytes)
      TCP: Hash tables configured (established 1024 bind 1024)
      TCP reno registered
      NET: Registered protocol family 1
      squashfs: version 4.0 (2009/01/31) Phillip Lougher
      msgmni has been set to 46
      io scheduler noop registered
      io scheduler cfq registered (default)
      Realtek GPIO Driver for Flash Reload Default
      Serial: 8250/16550 driver, 1 ports, IRQ sharing disabled
      serial8250: ttyS0 at MMIO 0x18002000 (irq = 8) is a 16550A
      PPP generic driver version 2.4.2
      MPPE/MPPC encryption/compression module registered
      NET: Registered protocol family 24
      Realtek WLAN driver - version 1.7 (2015-10-30)(SVN:Unversioned symlink)
      Adaptivity function - version 9.5.20
      CFG0 
      40MHz Clock Source
      Find Port=0 Device:Vender ID=818c10ec
      IS_RTL8192F_SERIES value8 = d 
      MACHAL_version_init
      [MACFM_software_init 148]wifi hal support Mac function = 0x84860
      RFE TYPE =3
      
      
      #######################################################
      SKB_BUF_SIZE=2472 MAX_SKB_NUM=400
      #######################################################
      
      [MACFM_software_init 148]wifi hal support Mac function = 0x84860
      RFE TYPE =3
      [MACFM_software_init 148]wifi hal support Mac function = 0x84860
      RFE TYPE =3
      [MACFM_software_init 148]wifi hal support Mac function = 0x84860
      RFE TYPE =3
      [MACFM_software_init 148]wifi hal support Mac function = 0x84860
      RFE TYPE =3
      [MACFM_software_init 148]wifi hal support Mac function = 0x84860
      RFE TYPE =3
      
      
      
      Probing RTL8186 10/100 NIC-kenel stack size order[3]...
      chip name: 8196C, chip revid: 0
      eth0 added. vid=9 Member port 0x10f...
      eth1 added. vid=8 Member port 0x10...
      rtl819x_dlink Generic Netlink family is registered.
      SPI INIT
      flash device: 0x400000 at 0xbfe00000
       ------------------------- Force into Single IO Mode ------------------------ 
      |No chipID  Sft chipSize blkSize secSize pageSize sdCk opCk      chipName    |
      | 0 c22016h  0h  400000h  10000h   1000h     100h   50    0        MX25L3206E|
       ---------------------------------------------------------------------------- 
      SPI flash(MX25L3206E) was found at CS0, size 0x400000
      flash_bank_1: squashfs filesystem found at offset 0x175000
      Creating 7 MTD partitions on "flash_bank_1":
      0x000000000000-0x000000010000 : "boot"
      0x000000010000-0x000000020000 : "MAC"
      0x000000020000-0x000000030000 : "config"
      0x000000030000-0x000000175000 : "kernel"
      0x000000175000-0x000000400000 : "rootfs"
      0x000000030000-0x000000400000 : "Linux"
      0x000000000000-0x000000400000 : "ALL"
      Netfilter messages via NETLINK v0.30.
      nf_conntrack version 0.5.0 (512 buckets, 2048 max)
      ctnetlink v0.93: registering with nfnetlink.
      ip_tables: (C) 2000-2006 Netfilter Core Team
      TCP cubic registered
      NET: Registered protocol family 10
      ip6_tables: (C) 2000-2006 Netfilter Core Team
      NET: Registered protocol family 17
      Bridge firewalling registered
      Ebtables v2.0 registered
      802.1Q VLAN Support v1.8 Ben Greear &lt;greearb@candelatech.com&gt;
      All bugs added by David S. Miller &lt;davem@redhat.com&gt;
      Netlink[Kernel] create socket for igmp ok.
      Realtek FastPath:v1.03
      nlmon: nlmon_init entry
      VFS: Mounted root (squashfs filesystem) readonly on device 31:4.
      Freeing unused kernel memory: 120k freed
      D-link init started
      Jan  1 00:00:08 init[1]: Kernel threads-max value (128) is too small. Set it to 512.
      
      updateboot: bootloader up to date
      gpiom: module license 'Proprietary' taints kernel.
      Disabling lock debugging due to kernel taint
      gpiom: module starting ...
      gpiom: using profile DIR_615X_RT8196E.
      gpiom: button support enabled.
      gpiom: led support enabled.
      init_pre_boot: -----&gt; OK.
      Jan  1 00:00:01 read config[1]: tar error
      
      
      read_and_validate_conf - config: 0, res: 1
      Jan  1 00:00:01 read config[1]: tar error
      
      
      read_and_validate_conf - config: 1, res: 1
      Use /etc/config.default
      Lenght of avalible memory for title 149 bytes
      resident starting...
      Event pipe size is 4096 bytes
      Initializing device...
      
      Initializing /dev/mtd1 RLX...
      Intialize wifi calibration (-1)...
      MTD RLX data is latest!!!
      
      Jan  1 00:00:03 autoupdate[37]: Config reset
      
      
      Init netfilter
      nf_conntrack_rtsp v0.6.21 loading
      nf_nat_rtsp v0.6.21 loading
      Check SSID
      Do preinit ifaces
      Set[RTL_NIC]:(success): Dev eth0 is opened!
       mac 04:ba:d6:18:51:f6 on iface eth[RTL_NIC]:(success): Dev eth1 is opened!
      0 - ADDRCONF(NETDEV_UP): eth1: link is not ready
      OK
      Set mac 04:ba:d6:18:51:f5 on iface eth1 - OK
      Jan  1 00:00:03 sched_set_task_activity[37]: Cannot open pipe
      
      Jan  1 00:00:03 rlx_wifi_mibs[37]: iwpriv_set_mib: set_mib (wlan0) failed: Operation not permitted
      
      
      Jan  1 00:00:03 rlx_wifi_mibs[37]: Can't set mib tssi_enable (wlan0)
      
      
      Jan  1 00:00:03 rlx_wifi_mibs[37]: iwpriv_set_mib: set_mib (wlan0) failed: Operation not permitted
      
      
      Jan  1 00:00:03 rlx_wifi_mibs[37]: Can't set mib thermal1 (wlan0)
      
      
      Jan  1 00:00:03 rlx_wifi_mibs[37]: iwpriv_set_mib: set_mib (wlan0) failed: Operation not permitted
      
      
      Jan  1 00:00:03 rlx_wifi_mibs[37]: Can't set mib thermal2 (wlan0)
      
      
      Jan  1 00:00:03 libshared rtl:start_wifi[37]: begin
      
      Jan  1 00:00:03 start_wifi[37]: start on br= br0
      
      Jan  1 00:00:04 DMS_NL_API[37]: Cannot find d-------&gt; Set MIB from /etc/Wireless/RTL8192CD.dat
      eviCFGFILE set_mib "wds_enable=0" failed 
      cCFGFILE set_mib "wds_pure=0" failed 
      eCFGFILE set_mib "wds_priority=1" failed 
      :CFGFILE set_mib "wds_encrypt=0" failed 
       CFGFILE set_mib "wds_num=0" failed 
      br0
      
      &lt;------- Set MIB from /etc/Wireless/RTL8192CD.dat Success
      Jan  1 00:00:04 DMS_ROUTE_ERROR[37]: ADD 239.255.255.250 via (null) dev br0 metr 0 table 254 (configure_config_file)
      
      Jan  1 00:00:04 start_wifi[37]: pin = 29123957
      
      
      Jan  1 00:00:04 config_ssid_params[37]: begin
      
      Jan  1 00:00:04 config_ssid_params[37]: ifname = wlan0
      
      clock 40MHz
      Jan  1 00:00:05 execWPACommands[37]: auth daemon isn't needed!
      
      
      Jan  1 00:00:05 start_wifi[37]: Starting iwcontrol...
      
      
      Do clear ifaces
      set mac 04:ba:d6:18:51:f6 on br0
      set mac 04:ba:d6:18:51:f5 on eth1
      Jan  1 00:00:05 try_get_uuid[37]: Unable to open uuid.conf
      
      init_lan: iface = br0
      Register to wlan0
      br0: No such device
      init ipfilter
      iwcontrol RegisterPID to (wlan0)
      init vserver
      start urlfilter
      LLmnr bindtodevice error: No such device
      cleanup pidfile /tmp/locdns.br0.pid
      m
      unable to create recv socket
      init rlx linux vlans
      device eth0.2 entered promiscuous mode
      device eth0 entered promiscuous mode
      device wlan0 entered promiscuous mode
      [RTL_NIC]: Add VLAN 2 with portmask: 0x10f, tagmask: 0x100 to switch core
      [RTL_NIC]: Update netif for eth0, vid: 2, portmask: 0x10f
      [RTL_NIC]: Add VLAN 1 with portmask: 0x10, tagmask: 0x0 to switch core
      [RTL_NIC]: Update netif for eth1, vid: 1, portmask: 0x10
      br0: port 2(wlan0) entering learning state
      br0: port 1(eth0.2) entering learning state
      br0: port 2(wlan0) entering forwarding state
      br0: port 1(eth0.2) entering forwarding state
      LocDNS started: NetBIOS - ok, LLMNR - ok
      init Realtek HW_NAT
      init wan[RTL_NIC]:(success): Dev eth1 is closed!
      s
      Intialize wan[RTL_NIC]:(success): Dev eth1 is opened!
      .....
      ADDRCONF(NETDEV_UP): eth1: link is not ready
      
      Set mac 04:ba:d6:18:51:f5 on iface eth1 - OK
      Set mtu 1500 on iface eth1 - OK
      init macfilter
      start services
      d-link channel[1+2+3+4+5] = 2590
      d-link channel[2+3+4+5+6] = 2890
      d-link channel[3+4+5+6+7] = 3120
      d-link channel[4+5+6+7+8] = 3240
      d-link channel[5+6+7+8+9] = 3260
      d-link channel[6+7+8+9+10] = 3220
      d-link channel[7+8+9+10+11] = 3080
      d-link channel[8+9+10+11+12] = 2760
      d-link channel[9+10+11+12+13] = 2380
      d-link select channel = 13 + 9
      start tr069...
      init DOS filter
      
              
      `,
  },
  {
    title: 'Report 3',
    description:
      `Now is the winter of our discontent Made glorious summer by this sun of York. 
      And all the clouds that lour'd upon our house In the deep bosom of the ocean buried. 
      Now are our brows bound with victorious wreaths. Our bruised arms hung up for monuments; 
      Our stern alarums changed to merry meetings, Our dreadful marches to delightful measures. 
      Grim-visaged war hath smooth'd his wrinkled front; 
      And now, instead of mounting barded steeds To fright the souls of fearful adversaries. 
      He capers nimbly in a lady's chamber To the lascivious pleasing of a lute. 
      But I, that am not shaped for sportive tricks. 
      Nor made to court an amorous looking-glass. 
      I, that am rudely stamp'd, and want love's majesty To strut before a wanton ambling nymph; 
      I, that am curtail'd of this fair proportion`,
  },
  {
    title: 'Report 4',
    description:
      "Fog everywhere. Fog up the river, where it flows among green aits and meadows. Fog down the river, where it rolls deified among the tiers of shipping and the waterside pollutions of a great (and dirty) city. Fog on the Essex marshes, fog on the Kentish heights. Fog creeping into the cabooses of collier-brigs. Fog lying out on the yards and hovering in the rigging of great ships. Fog drooping on the gunwales of barges and small boats. Fog in the eyes and throats of ancient Greenwich pensioners, wheezing by the firesides of their wards. Fog in the stem and bowl of the afternoon pipe of the wrathful skipper, down in his close cabin. Fog cruelly pinching the toes and fingers of his shivering little apprentice boy on deck. Chance people on the bridges peeping over the parapets into a nether sky of fog, with fog all round them, as if they were up in a balloon and hanging in the misty clouds.",
  },
  {
    title: 'Report 5',
    description:
      "Fog everywhere. Fog up the river, where it flows among green aits and meadows. Fog down the river, where it rolls deified among the tiers of shipping and the waterside pollutions of a great (and dirty) city. Fog on the Essex marshes, fog on the Kentish heights. Fog creeping into the cabooses of collier-brigs. Fog lying out on the yards and hovering in the rigging of great ships. Fog drooping on the gunwales of barges and small boats. Fog in the eyes and throats of ancient Greenwich pensioners, wheezing by the firesides of their wards. Fog in the stem and bowl of the afternoon pipe of the wrathful skipper, down in his close cabin. Fog cruelly pinching the toes and fingers of his shivering little apprentice boy on deck. Chance people on the bridges peeping over the parapets into a nether sky of fog, with fog all round them, as if they were up in a balloon and hanging in the misty clouds.",
  },
  {
    title: 'Report 6',
    description:
      "Fog everywhere. Fog up the river, where it flows among green aits and meadows. Fog down the river, where it rolls deified among the tiers of shipping and the waterside pollutions of a great (and dirty) city. Fog on the Essex marshes, fog on the Kentish heights. Fog creeping into the cabooses of collier-brigs. Fog lying out on the yards and hovering in the rigging of great ships. Fog drooping on the gunwales of barges and small boats. Fog in the eyes and throats of ancient Greenwich pensioners, wheezing by the firesides of their wards. Fog in the stem and bowl of the afternoon pipe of the wrathful skipper, down in his close cabin. Fog cruelly pinching the toes and fingers of his shivering little apprentice boy on deck. Chance people on the bridges peeping over the parapets into a nether sky of fog, with fog all round them, as if they were up in a balloon and hanging in the misty clouds.",
  },
]



export default function CustomizedTables({ handleOpen, setCurrentReport }) {


  return (
    <TableContainer component={Paper}>
      <Table sx={{ width: '100%' }} aria-label='customized table'>
        <TableHead>
          <TableRow>
            <StyledTableCell>Report</StyledTableCell>
            <StyledTableCell align='right'>Actions</StyledTableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {rows.map((ele) => (
            <StyledTableRow key={ele.title}>
              <StyledTableCell component='th' scope='row'>
                {ele.title}
              </StyledTableCell>
              <StyledTableCell align='right'>
                <Button onClick={() => handleOpen(ele)}>Analyze</Button>
              </StyledTableCell>
            </StyledTableRow>
          ))}
        </TableBody>
      </Table>
    </TableContainer>
  )
}
