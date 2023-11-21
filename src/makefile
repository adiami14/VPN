
#	gd / gc infinity flags
DEBUG = -ansi -pedantic-errors -Wall -Wextra -g
RELEASE = -ansi -pedantic-errors -Wall -Wextra -DNDEBUG -O3

CFLAGS = $(DEBUG)
CPPFLAGS = 

OBJS = $(TARGET).o vpn_server_test.o network_utils.o
OBJS2 = $(TARGET).o vpn_client_test.o network_utils.o 
OBJS3 = $(TARGET).o network_utils.o
SSLOBJ = vpn_ssl.o network_utils.o $(TARGET).o

TARGET = vpn
PROJECTDIR := cyber


OBJDIR := ~/git/$(PROJECTDIR)
SRCDIR := $(OBJDIR)/src/$(TARGET)
INCDIR := $(OBJDIR)/include
TESDIR := $(OBJDIR)/test/$(TARGET)

.PHONY: clean all

$(TARGET): $(OBJS) $(TARGET)_client_test.o ssl_v
	cc $(CFLAGS) $(OBJS) -o $(TARGET)_server -L$(INCDIR)/$(TARGET).h 
	cc $(CFLAGS) $(OBJS2) -o $(TARGET)_client -L$(INCDIR)/$(TARGET).h
	cc $(CFLAGS) dtls_udp_echo.o $(SSLOBJ) -o ssl_vpn -lssl -lcrypto
	cc $(CFLAGS) final_ssl_vpn.c $(SSLOBJ) -o final -lssl -lcrypto
	cc dtls_udp_echo.c -g -o test -lssl -lcrypto
#	cc -g $(SRCDIR)/dtls.c -o dtls -lssl -lcrypto
#	cc -g $(SRCDIR)/dtls_client.c -o dtls_client -lssl -lcrypto
#	cc $(CFLAGS) $(SRCDIR)/ssl/server.c -o server -L/usr/lib -lssl -lcrypto
#	cc -Wall $(SRCDIR)/ssl/client.c -o client -L/usr/lib -lssl -lcrypto
#	cc $(CFLAGS) $(TARGET)_ssl.c -o $(TARGET)_ssl -L/usr/lib -lssl -lcrypto
#	cc $(CFLAGS) $(TESDIR)/unit_testing/test_new_connection_client.c $(TARGET).o network_utils.o -o test_new_connection_client -L$(INCDIR)/$(TARGET).h
#	cc $(CFLAGS) $(TESDIR)/unit_testing/test_new_connection_server.c $(TARGET).o network_utils.o -o test_new_connection_server -L$(INCDIR)/$(TARGET).h

all: $(TARGET) lib$(TARGET).a 
	cc $(DEBUG) $^ -o $(TARGET) -L$(INCDIR)/$(TARGET).h -I$(TARGET).ar

vpn_server_test.o: $(TESDIR)/vpn_server_test.c $(INCDIR)/$(TARGET).h
	cc $(CFLAGS) -c $< -o $@ 

$(TARGET).o: $(SRCDIR)/$(TARGET).c $(INCDIR)/$(TARGET).h
	cc $(CFLAGS) -c $< -o $@ 

$(TARGET)_client_test.o:$(TESDIR)/$(TARGET)_client_test.c $(INCDIR)/$(TARGET).h
	cc $(CFLAGS) -c $< -o $@ 

network_utils.o: $(SRCDIR)/network_utils.c $(INCDIR)/network_utils.h
	cc $(CFLAGS) -c $< -o $@ 

ssl_v: $(TESDIR)/dtls_udp_echo.c $(SRCDIR)/vpn_ssl.c
	cc $(CFLAGS) $(TESDIR)/dtls_udp_echo.c -c -L$(INCDIR)/vpn_ssl.h
	cc $(CFLAGS) $(SRCDIR)/vpn_ssl.c -c -L$(INCDIR)/vpn_ssl.h

lib$(TARGET).a: $(TARGET).o $(INCDIR)/$(TARGET).h
	ar rcs $@ $^
	rm -f $(OBJS)
	

.PHONY : clean
clean:
	rm -f *.o vpn_demo_server vpn_demo_client test_new_connection_client test_new_connection_server vpn vpn_client vpn_server vpn_demo server client vpn_ssl ssl_vpn
.PHONY : cleanll
cleanll:
	rm -f $(OBJS) $(TARGET) lib$(TARGET).a
	
debug: $(OBJS)
	gcc $(DEBUG) $(OBJS) -o $(TARGET)
		
release: $(OBJS)
	gcc $(RELEASE) $(OBJS) -o $@

git:
	git add .
	git commit -m "$(TARGET)"
	git push

install open_ssl:
	sudo apt-get install libssl-dev

rest:
	sudo ip route flush table main
	sudo systemctl restart NetworkManager
	sudo iptables -F
	sudo iptables -t nat -F

cert_and_key:
	sudo openssl genpkey -algorithm RSA -out $(SRCDIR)/cert/client-key.pem
	sudo openssl req -new -key $(SRCDIR)/cert/client-key.pem -x509 -days 365 -out $(SRCDIR)/cert/client-cert.pem
	sudo openssl genpkey -algorithm RSA -out $(SRCDIR)/cert/server-key.pem
	sudo openssl req -new -key $(SRCDIR)/cert/server-key.pem -x509 -days 365 -out $(SRCDIR)/cert/server-cert.pem

vlg:
	valgrind --leak-check=yes --track-origins=yes ./$(TARGET)
	
vlgdb:
	valgrind -q --vgdb-error=0 ./$(TARGET)

.PHONY : open
open: 
	code $(SRCDIR)/$(TARGET).c 
	code $(INCDIR)/$(TARGET).h 
	code $(TESDIR)/vpn_server_test.c  
	code $(TESDIR)/vpn_client_test.c
	code $(TESDIR)/dtls_udp_echo.c &
	code $(INCDIR)/$(TARGET)_ssl.h &
	code $(INCDIR)/network_utils.h &
	code $(SRCDIR)/makefile 
	code $(SRCDIR)/vpn_ssl.c
	
	
start:
	mkdir $(TESDIR)
	mkdir $(SRCDIR)
	code $(SRCDIR)/$(TARGET).c &
	code $(INCDIR)/$(TARGET).h &
	code $(TESDIR)/$(TARGET)_test.c & 
	cp ~/git/makefile $(SRCDIR)/makefile
	code $(SRCDIR)/makefile

remove:
	rm -R $(TESDIR)
	rm -R $(SRCDIR)
copy:
	cp ~/git/makefile $(SRCDIR)

.PHONY : touch
touch: 
	touch $(TARGET).o 
	touch main.o 
	echo "every one was touched :)"
