VCOMMON = src/common/
VCLIENT = src/client/
VSERVER = src/server/
VBUILD = build/
OS = $(shell uname)

$(info ====================================)
$(info SECURE MESSAGE PROJECT)
$(info Automatic Environment Generation)
$(info ====================================)
$(info )  
$(info Detected Operating System: $(OS))  

ifeq ($(OS), Linux)
CRYPTOFLAGS = -lssl -lcrypto #i remove the -lcurses linked library since we'll not implement the GUI anymore
THREADFLAGS = -pthread

all: clean build server client

client:
	g++ $(VCLIENT)mainClient.cpp $(VCLIENT)client.cpp $(VCOMMON)network.cpp $(VCOMMON)cryptography.cpp $(VCOMMON)utility.cpp -o $(VBUILD)client $(THREADFLAGS) $(CRYPTOFLAGS) 
server: 
	g++ $(VSERVER)server.cpp $(VCOMMON)cryptography.cpp $(VCOMMON)utility.cpp  -o $(VBUILD)server $(THREADFLAGS) $(CRYPTOFLAGS) 
build: 
	mkdir $(VBUILD)
clean:
	rm -rf $(VBUILD)

else
$(info --- ERROR: Operating System not supported yet!)
$(info --- Sorry, we support the following OS: Linux)

all: clean
clean:
	rm -rf $(VBUILD)
endif
