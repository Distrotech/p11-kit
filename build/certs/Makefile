
# Note that nothing here is distributed. It just lives in the git repository
# We copy everything into its final location, and those test files are
# distributed in the tarballs

TRUST = ../../trust/tests

prepare-certs:
	cp -v cacert3.der $(TRUST)/input/anchors
	cp -v cacert3.der $(TRUST)/files
	cp -v cacert3.der $(TRUST)/files
	openssl x509 -in cacert3.der -inform DER -out $(TRUST)/files/cacert3.pem
	openssl x509 -in cacert3.der -inform DER -out $(TRUST)/files/cacert3.pem
	cat $(TRUST)/files/cacert3.pem $(TRUST)/files/cacert3.pem > $(TRUST)/files/cacert3-twice.pem
	openssl x509 -in cacert3.der -inform DER -out $(TRUST)/files/cacert3-trusted.pem \
		-addtrust serverAuth -addreject emailProtection \
		-setalias "Custom Label"
	cp $(TRUST)/files/cacert3-trusted.pem $(TRUST)/files/cacert3-trusted-server-alias.pem
	openssl x509 -in cacert3.der -inform DER -out $(TRUST)/files/cacert3-trusted-alias.pem \
		-setalias "Custom Label"
	openssl x509 -in cacert3.der -inform DER -out $(TRUST)/files/cacert3-distrust-all.pem \
		-addreject serverAuth -addreject clientAuth -addreject codeSigning \
		-addreject emailProtection -addreject ipsecEndSystem -addreject ipsecTunnel \
		-addreject ipsecUser -addreject timeStamping
	openssl x509 -in verisign-v1.der -inform DER -out $(TRUST)/files/verisign-v1.pem \
		-setalias "Custom Label"
	cat $(TRUST)/files/cacert3-trusted-server-alias.pem \
		$(TRUST)/files/verisign-v1.pem > $(TRUST)/files/multiple.pem
	cp -v cacert-ca.der $(TRUST)/input
	cp -v cacert-ca.der $(TRUST)/files
	openssl x509 -in redhat-newca.der -inform DER -out $(TRUST)/files/distrusted.pem \
		-addreject clientAuth -setalias "Red Hat Is the CA"
	cp -v $(TRUST)/files/distrusted.pem $(TRUST)/input
	cp -v self-server.der $(TRUST)/input/blacklist
	cp -v self-signed-with-eku.der $(TRUST)/files
	cp -v self-signed-with-ku.der $(TRUST)/files
	cp -v testing-ca.der $(TRUST)/input/anchors
	cp -v testing-server.der $(TRUST)/files

# Rebuild the self-signed certificates. This is almost never necessary and
# will require other changes in the code, mostly here as documentation
build-self-signed:
	openssl req -new -x509 -outform DER -out self-signed-with-eku.der \
		-newkey rsa -keyout /dev/null -nodes -subj /CN=self-signed-with-eku.example.com \
		-config with-eku.conf -set_serial 888 -extensions v3_ca
	openssl req -new -x509 -outform DER -out self-signed-with-ku.der \
		-newkey rsa -keyout /dev/null -nodes -subj /CN=self-signed-with-ku.example.com \
		-config with-ku.conf -set_serial 888 -extensions v3_ca
	openssl req -new -x509 -outform DER -out distant-end-date.der \
		-newkey rsa:512 -keyout /dev/null -nodes -subj /CN=far-in-the-future.example.com \
		-config with-ku.conf -set_serial 999 -extensions v3_ca -days 20000
