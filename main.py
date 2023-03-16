import pandas as pd
from fyers_api import accessToken
from fyers_api import fyersModel
from pymongo import MongoClient, DESCENDING
import requests
import json
import time
import pandas as pd
import datetime as dt
import pyotp
from urllib.parse import urlparse, parse_qs
import numpy as np
import toml


def send_message_telegram(chat_id, text):
    url = "https://api.telegram.org/bot{}/sendMessage".format(bot_token)
    data = {"chat_id": chat_id, "text": text}

    r = requests.post(url, json=data).json()
    print(r)
    print("inside send_message_bot")


# Function to get fyers token


def fyers_login():

    # create a session
    session = accessToken.SessionModel(
        client_id=client_id,
        secret_key=secret_key,
        redirect_uri=redirect_uri,
        response_type=response_type,
        grant_type=grant_type,
        state=state,
        nonce=nonce,
    )

    # Find today's date
    curr_time_dec = time.localtime(time.time())
    date = time.strftime("%Y-%m-%d", curr_time_dec)

    # Create a dictionary to store tokens
    token = {"Date": date}

    # code to generate auth code
    headers = {
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.102 Safari/537.36"
    }
    with requests.Session() as s:

        body = {"fy_id": user_id, "app_id": "2"}
        r = s.request(
            "POST",
            "https://api-t2.fyers.in/vagator/v2/send_login_otp",
            data=json.dumps(body),
            headers=headers,
            allow_redirects=True,
        )

        totp = pyotp.TOTP(totp_token).now()
        request_key = r.json()["request_key"]
        body = {"request_key": request_key, "otp": totp}
        r = s.request(
            "POST",
            "https://api-t2.fyers.in/vagator/v2/verify_otp",
            data=json.dumps(body),
            headers=headers,
            allow_redirects=True,
        )

        request_key = r.json()["request_key"]
        body = {"request_key": request_key, "identity_type": "pin", "identifier": pin}
        r = s.request(
            "POST",
            "https://api-t2.fyers.in/vagator/v2/verify_pin",
            data=json.dumps(body),
            headers=headers,
            allow_redirects=True,
        )
        refresh_token = r.json()["data"]["refresh_token"]
        access_token = r.json()["data"]["access_token"]

        payload = {
            "fyers_id": "DA00190",
            "app_id": "HJ2321XETS",
            "redirect_uri": "https://127.0.0.1",
            "appType": "100",
            "code_challenge": "",
            "state": "private",
            "scope": "",
            "nonce": "private",
            "response_type": "code",
            "create_cookie": True,
        }
        headers = {
            "authority": "api.fyers.in",
            "accept": "*/*",
            "accept-language": "en-US,en;q=0.9",
            "content-type": "application/json; charset=UTF-8",
            "authorization": "Bearer " + access_token,
            "origin": "https://api.fyers.in",
            "referer": "https://api.fyers.in/api/v2/generate-authcode?client_id=HJ2321XETS-100&redirect_uri=https%3A%2F%2F127.0.0.1&response_type=code&state=private&nonce=private",
            "sec-ch-ua": '"Google Chrome";v="105", "Not)A;Brand";v="8", "Chromium";v="105"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-origin",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36",
        }

        response = requests.request(
            "POST",
            "https://api.fyers.in/api/v2/token",
            headers=headers,
            data=json.dumps(payload),
        )
        redirect_url = response.json()["Url"]
        qs = parse_qs(redirect_url)
        auth_code = qs["auth_code"][0]
        # print(f"auth_code : {auth_code}")

        # code to get access token
        session.set_token(auth_code)
        res = session.generate_token()
        access_token = res["access_token"]
        token["access_token"] = access_token
        # print(f"access_token : {access_token}")

        # create fyers object
        fyers = fyersModel.FyersModel(client_id=client_id, token=access_token)
        # print(fyers.get_profile())

        # save token in the database
        mongo_url = config["mongo_db"]["mongo_url"]
        mongo = MongoClient(mongo_url)
        mydb = mongo["test"]
        coll = mydb["tokens-akshay"]

        coll.insert_one(token)

    return token


# Function to login to fyers account and get token from database
def get_token(name):
    mongo_url = config["mongo_db"]["mongo_url"]
    mongo = MongoClient(mongo_url)
    mydb = mongo["test"]

    coll_name = "tokens-" + str(name)
    coll = mydb[coll_name]

    # Find the login details
    token = list(coll.find())[-1]
    # print(token)
    return token


# Fetch data using historical api
def get_data(bnfut_symbol):
    max_tries = 0

    to_date = dt.datetime.today().strftime("%Y-%m-%d")
    from_date = (dt.datetime.today() - dt.timedelta(10)).strftime("%Y-%m-%d")

    data = {
        "symbol": bnfut_symbol,
        "resolution": "1",
        "date_format": "1",
        "range_from": from_date,
        "range_to": to_date,
        "cont_flag": "1",
    }

    while max_tries < 5:
        try:
            response = fyers.history(data)
            df = pd.DataFrame(
                response["candles"],
                columns=["DateTime", "Open", "High", "Low", "Close", "Volume"],
            )
            df["Date"] = df["DateTime"].apply(
                lambda x: dt.datetime.fromtimestamp(x).strftime("%Y-%m-%d")
            )
            df["Time"] = df["DateTime"].apply(
                lambda x: dt.datetime.fromtimestamp(x).strftime("%H:%M:%S")
            )
            df["DateTime"] = df["DateTime"].apply(
                lambda x: dt.datetime.fromtimestamp(x)
            )
            df = df.set_index("DateTime")
            df = df.resample("5T").agg(
                {
                    "Open": "first",
                    "High": "max",
                    "Low": "min",
                    "Close": "last",
                    "Volume": "sum",
                }
            )
            df = df.dropna()

            # df = df[["DateTime","Date","Time","Open","High","Low","Close","Volume"]]

            return df

        except:
            if max_tries == 5:
                break

            max_tries = max_tries + 1

    return -1


# Function to find supertrend value
def supertrend(df, atr_period, multiplier):

    high = df["High"]
    low = df["Low"]
    close = df["Close"]

    price_diffs = [high - low, high - close.shift(), close.shift() - low]

    true_range = pd.concat(price_diffs, axis=1)
    true_range = true_range.abs().max(axis=1)

    atr = true_range.ewm(alpha=1 / atr_period, min_periods=atr_period).mean()

    hl2 = (high + low) / 2

    final_upperband = upperband = hl2 + (multiplier * atr)
    final_lowerband = lowerband = hl2 - (multiplier * atr)
    s_t = atr

    supertrend = [True] * len(df)

    for i in range(1, len(df.index)):
        curr, prev = i, i - 1

        if close[curr] > final_upperband[prev]:
            supertrend[curr] = True

        elif close[curr] < final_lowerband[prev]:
            supertrend[curr] = False

        else:
            supertrend[curr] = supertrend[prev]

            if (
                supertrend[curr] == True
                and final_lowerband[curr] < final_lowerband[prev]
            ):
                final_lowerband[curr] = final_lowerband[prev]

            if (
                supertrend[curr] == False
                and final_upperband[curr] > final_upperband[prev]
            ):
                final_upperband[curr] = final_upperband[prev]

        if supertrend[curr] == True:
            final_upperband[curr] = np.nan
            s_t[curr] = final_lowerband[curr]

        else:
            final_lowerband[curr] = np.nan
            s_t[curr] = final_upperband[curr]

    return pd.DataFrame(
        {str(atr_period) + "_" + str(multiplier) + "_Supertrend": s_t}, index=df.index
    )


# Function to find ltp of an instrument
def get_ltp(symbol):
    return fyers.quotes({"symbols": symbol})["d"][0]["v"]["lp"]


# Function to create trading symbol
def get_trading_symbol(expiry_subsymbol, strike, option_type):
    return "NSE:BANKNIFTY" + expiry_subsymbol + str(strike) + option_type


def find_option_strike(nearest_premium, option_type):

    opt_strike = derivatives_list[
        (derivatives_list["Instrument"] == "BANKNIFTY")
        & (derivatives_list["Exchange Instrument type"] == 14)
        & (derivatives_list["Expiry date"] == weekly_expiry_date_epoch)
        & (derivatives_list["Option type"] == option_type)
    ]["Symbol ticker"].to_list()

    count = round(len(opt_strike) / 40) + 1

    opt_strike_dict = {}

    for c in range(count):
        opt_strike_str = ",".join(opt_strike[c * 40 : c * 40 + 40])

        for i in fyers.quotes({"symbols": opt_strike_str})["d"]:
            opt_strike_dict[i["n"]] = i["v"]["lp"]

    closest_key = None
    closest_diff = None

    for key, value in opt_strike_dict.items():
        diff = abs(value - nearest_premium)
        if closest_diff is None or diff < closest_diff:
            closest_key = key
            closest_diff = diff

    return closest_key


# ---------------------------#

# load the config file
config = toml.load("pyproject.toml")

# bot_token = "1733931112:AAGdRjwf10J9L2-Pg6SZ4o2eLq_nQu7Dze0"
bot_token = config["telegram"]["bot_token"]

# user details
user_id = config["fyers"]["user_id"]
client_id = config["fyers"]["client_id"]
secret_key = config["fyers"]["secret_key"]
redirect_uri = config["fyers"]["redirect_uri"]
totp_token = config["fyers"]["totp_token"]
pin = config["fyers"]["pin"]
response_type = "code"
grant_type = "authorization_code"
state = "private"
nonce = "private"


# Code to create a fyers object

is_async = False
token_object = get_token("akshay")
fyers = fyersModel.FyersModel(client_id=client_id, token=token_object["access_token"])


if fyers.get_profile()["s"] == "error":
    print("Access Token Expired!")
    print("Generating new access token...")
    token_object = fyers_login()
    fyers = fyersModel.FyersModel(
        client_id=client_id, token=token_object["access_token"]
    )


# code to find the latest expiry banknifty future symbol

derivatives_list = pd.read_csv(
    "https://public.fyers.in/sym_details/NSE_FO.csv", header=None
)
derivatives_list.columns = [
    "Fytoken",
    "Symbol Details",
    "Exchange Instrument type",
    "Minimum lot size",
    "Tick size",
    "ISIN",
    "Trading Session",
    "Last update date",
    "Expiry date",
    "Symbol ticker",
    "Exchange",
    "Segment",
    "Scrip code",
    "Instrument",
    "Underlying scrip code",
    "Strike price",
    "Option type",
    "a",
]
bnfut_symbol = (
    derivatives_list[
        (derivatives_list["Instrument"] == "BANKNIFTY")
        & (derivatives_list["Exchange Instrument type"] == 11)
    ]
    .sort_values("Expiry date")
    .iloc[0]["Symbol ticker"]
)

# Find latest weekly expiry date

weekly_expiry_date_epoch = (
    derivatives_list[
        (derivatives_list["Instrument"] == "BANKNIFTY")
        & (derivatives_list["Exchange Instrument type"] == 14)
    ]
    .sort_values("Expiry date")
    .iloc[0]["Expiry date"]
)
weekly_expiry_date = dt.datetime.fromtimestamp(weekly_expiry_date_epoch).strftime(
    "%Y-%m-%d"
)

# Find the expiry sub-symbol

YY = weekly_expiry_date[2:4]
MM = weekly_expiry_date[5:7]
dd = weekly_expiry_date[-2:]

if int(MM) < 10:
    MM = MM[-1]

expiry_subsymbol = YY + MM + dd


# Entry Condition Code

ce_position = {}
pe_position = {}
ce_position["flag"] = 0
pe_position["flag"] = 0

while (
    dt.datetime.now().strftime("%H:%M:%S") >= "09:20:00"
    and dt.datetime.now().strftime("%H:%M:%S") <= "16:57:00"
):

    try:

        df = get_data(bnfut_symbol)
        df["Supertrend"] = supertrend(df, 10, 3)
        close_value = df.iloc[-1]["Close"]
        supertrend_value = df.iloc[-1]["Supertrend"]

        # Main Entry
        if close_value > supertrend_value and pe_position["flag"] == 0:
            pe_position["strike"] = find_option_strike(100, "PE")
            pe_position["entry_price"] = get_ltp(pe_position["strike"])
            pe_position["sl_price"] = round(pe_position["entry_price"] * 1.5 * 20) / 20
            pe_position["qty"] = 25
            pe_position["entry_time"] = dt.datetime.now()

            print(f'SHORT: {pe_position["strike"]} at {pe_position["entry_price"]}')
            send_message_telegram(
                "-1001825639727",
                f'SHORT\n{pe_position["strike"]}\n@ {pe_position["entry_price"]}',
            )
            print(f'SL: {pe_position["strike"]} at {pe_position["sl_price"]}')
            send_message_telegram(
                "-1001825639727",
                f'SL PLACED\n{pe_position["strike"]}\n@ {pe_position["sl_price"]}',
            )

            pe_position["flag"] = 1
            continue

        if close_value < supertrend_value and ce_position["flag"] == 0:
            ce_position["strike"] = find_option_strike(100, "CE")
            ce_position["entry_price"] = get_ltp(ce_position["strike"])
            ce_position["sl_price"] = round(ce_position["entry_price"] * 1.5 * 20) / 20
            ce_position["qty"] = 25
            ce_position["entry_time"] = dt.datetime.now()

            print(f'SHORT: {ce_position["strike"]} at {ce_position["entry_price"]}')
            send_message_telegram(
                "-1001825639727",
                f'SHORT\n{ce_position["strike"]}\n@ {ce_position["entry_price"]}',
            )
            print(f'SL: {ce_position["strike"]} at {ce_position["sl_price"]}')
            send_message_telegram(
                "-1001825639727",
                f'SL PLACED\n{ce_position["strike"]}\n@ {ce_position["sl_price"]}',
            )

            ce_position["flag"] = 1
            continue

        # SL Check
        if pe_position["flag"] == 1:

            pe_strike_ltp = get_ltp(pe_position["strike"])
            print(pe_strike_ltp)

            if pe_strike_ltp >= pe_position["sl_price"]:

                pe_position["flag"] = 2  # PE SL Hit
                pe_position["exit_price"] = pe_position["sl_price"]
                pe_position["exit_time"] = dt.datetime.now()
                pe_position["exit_type"] = "SL-HIT"

                print(f'SL HIT: {pe_position["strike"]} at {pe_position["sl_price"]}')
                send_message_telegram(
                    "-1001825639727",
                    f'SL HIT\n{pe_position["strike"]}\n@ {pe_position["sl_price"]}',
                )

        if ce_position["flag"] == 1:

            ce_strike_ltp = get_ltp(ce_position["strike"])
            print(ce_strike_ltp)

            if ce_strike_ltp >= ce_position["sl_price"]:

                ce_position["flag"] = 2  # CE SL Hit
                ce_position["exit_price"] = ce_position["sl_price"]
                ce_position["exit_time"] = dt.datetime.now()
                ce_position["exit_type"] = "SL-HIT"

                print(f'SL HIT: {ce_position["strike"]} at {ce_position["sl_price"]}')
                send_message_telegram(
                    "-1001825639727",
                    f'SL HIT\n{ce_position["strike"]}\n@ {ce_position["sl_price"]}',
                )

        time.sleep(5)

    except:
        continue

# Send PNL to telegram group at 03:15 PM

if (
    dt.datetime.now().strftime("%H:%M:%S") >= "15:14:00"
    and dt.datetime.now().strftime("%H:%M:%S") <= "15:16:00"
):

    data = []
    mongo_url = config["mongo_db"]["mongo_url"]
    mongo = MongoClient(mongo_url)
    mydb = mongo["test"]
    pnl_col = mydb["systematic-strategy-sss"]

    if pe_position["flag"] == 2:
        pe_position["pnl"] = round(
            (pe_position["entry_price"] - pe_position["sl_price"]) * pe_position["qty"],
            2,
        )

        data.append(pe_position)

        print(f'PE PNL for {pe_position["strike"]}: Rs. {pe_position["pnl"]}')
        send_message_telegram(
            "-1001825639727",
            f'PE PNL for\n{pe_position["strike"]}\nRs. {pe_position["pnl"]}',
        )

    elif pe_position["flag"] == 1:

        pe_position["exit_price"] = get_ltp(pe_position["strike"])
        pe_position["pnl"] = round(
            (pe_position["entry_price"] - pe_position["exit_price"])
            * pe_position["qty"],
            2,
        )
        pe_position["exit_time"] = dt.datetime.now()
        pe_position["exit_type"] = "TIME-SQ-OFF"

        data.append(pe_position)

        print(f'PE PNL for {pe_position["strike"]}: Rs. {pe_position["pnl"]}')
        send_message_telegram(
            "-1001825639727",
            f'PE PNL for\n{pe_position["strike"]}\nRs. {pe_position["pnl"]}',
        )

    else:
        print("No PE Position Today")
        send_message_telegram("-1001825639727", "No PE Position Today")

    if ce_position["flag"] == 2:
        ce_position["pnl"] = round(
            (ce_position["entry_price"] - ce_position["sl_price"]) * ce_position["qty"],
            2,
        )

        data.append(ce_position)

        print(f'CE PNL for {ce_position["strike"]}: Rs. {ce_position["pnl"]}')
        send_message_telegram(
            "-1001825639727",
            f'CE PNL for\n{ce_position["strike"]}\nRs. {ce_position["pnl"]}',
        )

    elif ce_position["flag"] == 1:

        ce_position["exit_price"] = get_ltp(ce_position["strike"])
        ce_position["pnl"] = round(
            (ce_position["entry_price"] - ce_position["exit_price"])
            * ce_position["qty"],
            2,
        )
        ce_position["exit_time"] = dt.datetime.now()
        ce_position["exit_type"] = "TIME-SQ-OFF"

        data.append(ce_position)

        print(f'CE PNL for {ce_position["strike"]}: Rs. {ce_position["pnl"]}')
        send_message_telegram(
            "-1001825639727",
            f'CE PNL for\n{ce_position["strike"]}\nRs. {ce_position["pnl"]}',
        )

    else:
        print("No CE Position Today")
        send_message_telegram("-1001825639727", "No CE Position Today")

    # insert positions data into database
    pnl_col.insert_many(data)
