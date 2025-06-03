rule unknown_threat{

	strings:
		$url1: http://darkl0rd.com:7758/SSH-T
		$url2: http://darkl0rd.com:7758/SSH-One
		$path1: "/tmp/SSH-T"
		$path2: "/tmp/SSH-One"

    	condition:
        	all of them

}