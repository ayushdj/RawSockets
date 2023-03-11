rawhttpget:
	cp rawhttpget.py rawhttpget && chmod +x rawhttpget

clean:
	rm rawhttpget

2mb:
	sudo ./rawhttpget http://david.choffnes.com/classes/cs5700f22/2MB.log

10mb:
	sudo ./rawhttpget http://david.choffnes.com/classes/cs5700f22/10MB.log
