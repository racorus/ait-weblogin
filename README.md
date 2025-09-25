# ait-weblogin
chmod +x ait-weblogin.sh 

#
sudo bash -c 'cat > /root/.ait_login <<EOF
AIT_USER=your_username
AIT_PASS=your_password
EOF'
sudo chmod 600 /root/.ait_login
