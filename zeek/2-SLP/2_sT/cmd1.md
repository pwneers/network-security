zeek -C -r assignment_lecture10.pcap 2_sT/sT.zeek | grep '^172.16.0.1, 192.168.10.50' | grep -v ', Sr$' | cut -d, -f4 | sort | uniq -c
    958  S
     19  ShADaFf
     38  ShADadFf
     18  ShADadR
      1  ShADadfF
     36  ShADadfR
      3  ShAFaf
      4  ShAFf
    404  ShAR
      7  ShAdFaf
     33  ShAdFf
    394  ShR
      1  ^hSADadfR
      1  ^hSAR
      1  ^hSR
     31  ^r
