sudo mkdir -p /etc/mar
sudo touch /etc/mar/test
chmod -R 777 /etc/mar
cd /etc/mar
echo "deb [trusted=yes] https://packages.mozilla.org/apt mozilla main" | sudo tee -a /etc/apt/sources.list.d/mozilla.list
sudo apt-get update
sudo apt-get install -y python3 python3-pip python3-flask python3-cryptography python3-psutil python3-requests python3-flask-cors git
rm -rf Project-Mariana
git clone https://github.com/AdityaMitra5102/Project-Mariana.git
sudo cp Project-Mariana/mariana.service /etc/systemd/system
sudo chmod +x Project-Mariana/mariana
sudo cp -f Project-Mariana/mariana /usr/bin/mariana
sudo chmod +x /usr/bin/mariana
sudo systemctl daemon-reload
sudo systemctl enable mariana
sudo systemctl restart mariana
