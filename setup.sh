sudo mkdir -p /etc/mar
sudo touch /etc/mar/test
chmod -R 777 /etc/mar
cd /etc/mar
sudo apt-get update
sudo apt-get install -y python3 python3-pip python3-flask python3-cryptography python3-psutil python3-requests python3-flask-cors git
git clone https://github.com/AdityaMitra5102/Project-Mariana.git
sudo cp Project-Mariana/mariana.service /etc/systemd/system
sudo systemctl daemon-reload
sudo systemctl enable mariana
sudo systemctl restart mariana