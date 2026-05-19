sudo python3 -m venv blackwall
source ./blackwall/bin/activate
sudo chown -R $USER:$USER blackwall/

pip3 install -r requirements.txt

streamlit run app.py
