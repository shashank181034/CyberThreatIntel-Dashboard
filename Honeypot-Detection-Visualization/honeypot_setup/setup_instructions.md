# 1. Install Dependencies
sudo apt update
sudo apt install -y python3 python3-venv python3-pip authbind git

# 2. Create Cowrie User
sudo adduser --disabled-password --gecos "" cowrie

# 3. Clone Cowrie Repository
git clone https://github.com/cowrie/cowrie.git
sudo mv cowrie /home/cowrie/
sudo chown -R cowrie:cowrie /home/cowrie/cowrie

# 4. Setup Virtual Environment (as cowrie user)
sudo -u cowrie -H bash -lc "
cd ~/cowrie &&
python3 -m venv cowrie-env &&
source cowrie-env/bin/activate &&
pip install --upgrade pip &&
pip install -r requirements.txt
"

# 5. Configure Cowrie
# (You will need to edit manually)
sudo -u cowrie -H bash -lc "nano ~/cowrie/etc/cowrie.cfg"
# Change:
#   hostname = fake-kali
#   listen_port = 22

# 6. Start Honeypot
sudo -u cowrie -H bash -lc "cd ~/cowrie && source cowrie-env/bin/activate && authbind --deep ./bin/cowrie start"

# 7. Logs location
echo 'Logs stored at: /home/cowrie/cowrie/var/log/cowrie/cowrie.json'

# 8. Simulate Attack with Hydra (replace <Kali_IP> with your IP)
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://<Kali_IP> -s 22 -t 4 -V

Save (CTRL+O, ENTER, CTRL+X).

---
