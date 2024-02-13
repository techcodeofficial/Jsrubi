const cryptoJS = require('crypto-js')
const crypto = require('crypto');
const RSA = require('node-rsa');
const request = require('sync-request');
const fs = require("fs")
const sizeOf = require('buffer-image-size');
const audioMeta = require('audio-meta');
const WebSocket = require('ws');
const clc = require("cli-color");
const prompt = require("prompt-sync")({
  sigint: true
})
let error = clc.red.bold;
let notice = clc.blue.bold;
let success = clc.green.bold
let cyan = clc.cyan.bold
let magenta = clc.magenta.bold
let warn = clc.yellow.bold
class Encryption5 {
  constructor(auth) {
    this.key = cryptoJS.enc.Utf8.parse(this.secret(auth));
    this.iv = cryptoJS.enc.Hex.parse("00000000000000000000000000000000");
  }
  replaceCharAt(e, t, i) {
    return e.substring(0, t) + i + e.substring(t + i.length);
  }
  secret(e) {
    let t = e.substring(0, 8);
    let n = e.substring(16, 24) + e.substring(0, 8) + e.substring(24, 32) + e.substring(8, 16);
    let s = 0;
    let nArray = n.split('');
    while (s < nArray.length) {
      let e = nArray[s];
      if (e >= '0' && e <= '9') {
        t = String.fromCharCode((e.charCodeAt(0) - '0'.charCodeAt(0) + 5) % 10 + '0'.charCodeAt(0));
        nArray[s] = t;
      } else {
        t = String.fromCharCode((e.charCodeAt(0) - 'a'.charCodeAt(0) + 9) % 26 + 'a'.charCodeAt(0));
        nArray[s] = t;
      }
      s++;
    }
    return nArray.join('');
  }
  encrypt(text) {
    const encrypted = cryptoJS.AES.encrypt(text, this.key, {
      iv: this.iv,
      mode: cryptoJS.mode.CBC,
      padding: cryptoJS.pad.Pkcs7
    });
    return encrypted.toString();
  }
  decrypt(encryptedText) {
    const decrypted = cryptoJS.AES.decrypt(encryptedText, this.key, {
      iv: this.iv,
      mode: cryptoJS.mode.CBC,
      padding: cryptoJS.pad.Pkcs7
    });
    return decrypted.toString(cryptoJS.enc.Utf8);
  }
}
function replaceCharAt(e, t, i) {
  return e.substring(0, t) + i + e.substring(t + i.length);
}
function secret(e) {
  const t = e.substring(0, 8);
  const i = e.substring(8, 16);
  let n = e.substring(16, 24) + t + e.substring(24, 32) + i;
  let s = 0;
  while (s < n.length) {
    let char = n[s];
    if (char >= '0' && char <= '9') {
      const t = String.fromCharCode((char.charCodeAt(0) - '0'.charCodeAt(0) + 5) % 10 + '0'.charCodeAt(0));
      n = replaceCharAt(n, s, t);
    } else {
      const t = String.fromCharCode((char.charCodeAt(0) - 'a'.charCodeAt(0) + 9) % 26 + 'a'.charCodeAt(0));
      n = replaceCharAt(n, s, t);
    }
    s += 1;
  }
  return n;
}
class Encryption {
  constructor(auth, private_key = null) {
    this.auth = auth;
    this.key = Buffer.from(secret(auth), "utf-8").toString();
    this.iv = "00000000000000000000000000000000"
    if (private_key) {
      this.keypair = private_key.replace(/\\n/g, '\n');
    }
  }
  static changeAuthType(auth_enc) {
    let n = "";
    const lowercase = "abcdefghijklmnopqrstuvwxyz";
    const uppercase = lowercase.toUpperCase();
    const digits = "0123456789";
    for (let s of auth_enc) {
      if (lowercase.includes(s)) {
        n += String.fromCharCode(((32 - (s.charCodeAt(0) - 97)) % 26) + 97);
      } else if (uppercase.includes(s)) {
        n += String.fromCharCode(((29 - (s.charCodeAt(0) - 65)) % 26) + 65);
      } else if (digits.includes(s)) {
        n += String.fromCharCode(((13 - (s.charCodeAt(0) - 48)) % 10) + 48);
      } else {
        n += s;
      }
    }
    return n;
  }
  encrypt(text) {
    const keyHex = cryptoJS.enc.Utf8.parse(this.key);
    const ivHex = cryptoJS.enc.Hex.parse(this.iv);
    const encrypted = cryptoJS.AES.encrypt(text, keyHex, {
      iv: ivHex,
    });
    return encrypted.toString();
  }
  decrypt(text) {
    const keyHex = cryptoJS.enc.Utf8.parse(this.key);
    const ivHex = cryptoJS.enc.Hex.parse(this.iv);

    try {
      const decrypted = cryptoJS.AES.decrypt(text, keyHex, {
        iv: ivHex,
      });
      const decryptedText = decrypted.toString(cryptoJS.enc.Utf8);
      return decryptedText;
    } catch (e) {
      console.log(error("Decryption failed:"), e.message);
      return null;
    }
  }
  makeSignFromData(data) {
    try {
      const signer = crypto.createSign('RSA-SHA256');
      signer.update(data);
      const signature = signer.sign(this.keypair, 'base64');
      return signature;
    } catch (e) {
      console.log(e.message)
    }
  }
  static decryptRsaOaep(privateKey, data_enc) {
    const keyPair = crypto.createPrivateKey(privateKey);
    const dec = crypto.privateDecrypt({
      key: keyPair,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING
    }, Buffer.from(data_enc, 'base64'));
    return dec.toString('utf-8');
  }
  static rsaKeyGenerate() {
    const keyPair = new RSA({
      b: 1024
    });
    let publicKey = Encryption.changeAuthType(Buffer.from(keyPair.exportKey('pkcs1-public-pem'), 'binary').toString('base64'))
    let privateKey = keyPair.exportKey('pkcs1-private-pem');
    return {
      publicKey,
      privateKey
    }
  }
}
function getUrl(type) {
  if (type == "api") {
    return `https://messengerg2c${Math.floor(Math.random()*269)+1}.iranlms.ir/`
  } else {
    let socketApiList = [
            'wss://msocket1.iranlms.ir:80',
            'wss://jsocket1.iranlms.ir:80',
            'wss://jsocket2.iranlms.ir:80',
            'wss://jsocket3.iranlms.ir:80',
            'wss://jsocket4.iranlms.ir:80',
            'wss://jsocket5.iranlms.ir:80',
            'wss://nsocket6.iranlms.ir:80',
            'wss://nsocket7.iranlms.ir:80',
            'wss://nsocket8.iranlms.ir:80',
            'wss://nsocket9.iranlms.ir:80',
            'wss://nsocket10.iranlms.ir:80',
            'wss://nsocket11.iranlms.ir:80',
            'wss://nsocket12.iranlms.ir:80',
            'wss://nsocket13.iranlms.ir:80'
        ]
    let socketApi = socketApiList[Math.floor(Math.random() * socketApiList.length)]
    return socketApi
  }
}
function sendPost(data) {
  try {
    const header = {
      "Content-Type": "text/plain",
      "Accept": "application/json, text/plain, */*",
      "User-Agent": "Mozilla/5.0 (Linux; U; Android 12; en; M2004J19C Build/SP1A.210812.016) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/110.0.0.0 Mobile Safari/537.36",
      "Referer": "https://web.rubika.ir/"
    }
    const response = request("POST", getUrl("api"), {
      headers: header,
      json: data
    })
    return response.getBody().toString()
  } catch (e) {
    return "connection error"
  }
};

function makeTmpSession() {
  let chars = "abcdefghijklmnopqrstuvwxyz"
  let tmp = ""
  for (let i = 0; i < 32; i++) {
    tmp += chars[Math.floor(Math.random() * chars.length)]
  }
  return tmp
}

function formatPhoneNumber(phoneNumber) {
  phoneNumber = String(phoneNumber)
  const cleanedNumber = phoneNumber.replace(/\D/g, '');
  if (cleanedNumber.length == 10) {
    return '98' + cleanedNumber;
  } else if (cleanedNumber.length == 11 && cleanedNumber.startsWith('0')) {
    return '98' + cleanedNumber.substring(1);
  } else if (cleanedNumber.length == 12 && cleanedNumber.startsWith('98')) {
    return cleanedNumber
  } else {
    return false;
  }
}
class jsrubi {
  constructor(auth, key) {
    this.banner = notice(`
    @@ @@@@@@@  
    @@ @@@@@@@@ 
    @! @@!  @@@ ${magenta.italic("Coder")}${error(":")}${success.underline("MOHAMMAD AFRWZEH")}
    @! !@!  @!@ 
    !@ @!@!!@!  ${magenta.italic("GitHub")}${error(":")}${success.underline("@techcodeofficial")}
    !! !!@!@!   
    !: !!: :!!  ${magenta.italic("Npm")}${error(":")}${success.underline("npmjs.com/~techcode")}
!:  !: :!:  !:!
::  :: ::   ::: ${magenta.italic("Version")}${error(":")}${success.underline("1.3.1")}
 ::    :   : :  
       .    .   
            `)
    this.client = {
      "app_name": "Main",
      "app_version": "4.4.1",
      "platform": "Web",
      "package": "web.rubika.ir",
      "lang_code": "fa"
    }
    this.msgInfo = null
    console.log(this.banner)
    if (auth && key) {
      if (key.includes("-----BEGIN RSA PRIVATE KEY-----")) {
        this.auth = Encryption.changeAuthType(auth)
        key = key
        this.enc = new Encryption(auth, key)
      } else {
        try {
          key = JSON.parse(Buffer.from(key, 'base64').toString('utf-8'))['d'];
        } catch (e) {
          console.log(error("your key is not valid please check key"))
        }
        this.auth = auth;
        this.enc = new Encryption(Encryption.changeAuthType(auth), key)
      }
      this.checkSession = false
    } else {
      this.checkSession = auth + ".jsrubi"
      if (fs.readdirSync("./").includes(auth + ".jsrubi")) {
        let readFile = fs.readFileSync(auth + ".jsrubi", "utf-8")
        readFile = JSON.parse(readFile)
        this.key = readFile.privateKey
        this.auth = Encryption.changeAuthType(readFile.auth)
        this.enc = new Encryption(readFile.auth, this.key)
      } else {
        console.log(error("session is not found"))
        console.log(notice("creating new session...!"))
        let newSessionInfo = this.createSession(auth)
        fs.writeFileSync("./" + auth + ".jsrubi", JSON.stringify(newSessionInfo))
        let readFile = fs.readFileSync(auth + ".jsrubi", "utf-8")
        readFile = JSON.parse(readFile)
        this.key = readFile.privateKey
        this.auth = Encryption.changeAuthType(readFile.auth)
        this.enc = new Encryption(readFile.auth, this.key)
      }
    }
  }
  errorHandler(inData, tmp, registerDevice) {
    if (tmp) {
      let enc = new Encryption(tmp)
      let encode = enc.encrypt(JSON.stringify(inData))
      let enc_data = {
        'api_version': '6',
        'tmp_session': tmp,
        'data_enc': encode
      }
      let getResponse = sendPost(enc_data)
      let count = 0
      while (true) {
        count++
        if (getResponse == "connection error") {
          if (count == 10) {
            console.log(error("connection error try for connect again...!"))
            count = 0
          }
          getResponse = sendPost(enc_data)
        } else {
          let resultData = JSON.parse(enc.decrypt(JSON.parse(getResponse).data_enc))
          return resultData
          break;
        }
      }
    } else {
      let encode = this.enc.encrypt(JSON.stringify(inData))
      let signData = this.enc.makeSignFromData(encode)
      let enc_data = {
        "api_version": "6",
        "auth": this.auth,
        "data_enc": encode,
        "sign": signData
      }
      let getResponse = sendPost(enc_data)
      let count = 0
      while (true) {
        count++
        if (getResponse == "connection error") {
          if (count == 10) {
            console.log(error("connection error try for connect again...!"))
            count = 0
          }
          getResponse = sendPost(enc_data)
        } else {
          let resultData = JSON.parse(this.enc.decrypt(JSON.parse(getResponse).data_enc))
          return resultData
          break;
        }
      }
    }
  }
  sendCode(phone, pass_key) {
    let tmp = makeTmpSession()
    let inData = {
      "method": "sendCode",
      "input": {
        "phone_number": phone,
        "send_type": "SMS",
        "pass_key": pass_key
      },
      "client": this.client
    }
    return [this.errorHandler(inData, tmp),
            tmp]
  }
  signIn(phone_number, phone_code, phone_code_hash, tmp) {
    let rsaKey = Encryption.rsaKeyGenerate()
    let inData = {
      "method": "signIn",
      "input": {
        "phone_number": phone_number,
        "phone_code_hash": phone_code_hash,
        "phone_code": phone_code,
        "public_key": rsaKey.publicKey
      },
      "client": this.client
    }
    return [this.errorHandler(inData, tmp),
            tmp,
            rsaKey.privateKey]
  }
  registerDevice(sessionName, auth, privateKey) {
    let inData = {
      "method": "registerDevice",
      "input": {
        "token_type": "Web",
        "token": "",
        "app_version": "WB_4.3.3",
        "lang_code": "fa",
        "system_version": "Linux",
        "device_model": `JsRubi | ${sessionName}`,
        "device_hash": "050122004191210812016537364011000053736"
      },
      "client": this.client
    }
    let authSend = Encryption.changeAuthType(auth)
    let enc = new Encryption(auth, privateKey)
    let encode = enc.encrypt(JSON.stringify(inData))
    let signData = enc.makeSignFromData(encode)
    let enc_data = {
      "api_version": "6",
      "auth": authSend,
      "data_enc": encode,
      "sign": signData
    }
    let response = sendPost(enc_data)
    let result = JSON.parse(enc.decrypt(JSON.parse(response).data_enc))
    return result
  }
  createSession(sessionName) {
    const phonenumber = formatPhoneNumber(prompt(warn("Enter phone number: ")))
    let sendCodeData = this.sendCode(phonenumber)
    try {
      if (sendCodeData[0].data.status == "SendPassKey") {
        sendCodeData = this.sendCode(phonenumber, prompt(warn(`Enter pass key (${sendCodeData[0].data.hint_pass_key}): `)))
      }
      if (sendCodeData[0].data.status == "InvalidPassKey") {
        return `${error("passKey is invalid")} pass help is: ${warn.underline(sendCodeData[0].data.hint_pass_key)}`
      }
      let code = prompt(warn("Enter code digits: "))
      let result = this.signIn(phonenumber, code, sendCodeData[0].data.phone_code_hash, sendCodeData[1])
      if (result[0].data.status == "CodeIsInvalid") {
        console.log(error("code in invalid...!"))
      } else {
        let myAuth = Encryption.decryptRsaOaep(result[2], result[0].data.auth)
        let sessionData = {
          auth: myAuth,
          privateKey: result[2],
          user: result[0].data.user
        }
        let register = this.registerDevice(sessionName, myAuth, result[2])
        if (register.status == "OK") {
          console.log(success("session is created...!"))
        }
        return sessionData
      }
    } catch (e) {
      console.log(error("opps pleace check your phone number...!"))
    }
  }
  updateHandler(updates) {
    try {
        if (updates.length > 0) {
      if (this.msgInfo != updates[0].last_message.message_id) {
        this.msgInfo = updates[0].last_message.message_id
        return updates[0]
      }
    }
    } catch (e) {
        return updates
    }
  }
  onMessage(callback,showActivity,remove_notifications,filter_chats=[],filter_message=[],filter_chat=[]) {
    let dataToSend = {
      'api_version': '5',
      'auth': this.enc.auth,
      'method': 'handShake'
    }
    console.log(warn("connecting to websocket server...!"));
    const ws = new WebSocket(getUrl("socket"));
    let enc = new Encryption5(this.enc.auth);
    ws.on('open', function open() {
      ws.send(JSON.stringify(dataToSend));
      ws.send(JSON.stringify({}));
      console.log(success("connected to websocket server...!"));
    });
    ws.on('message', function message(data) {
      let result = JSON.parse(data)
      if (data.toString() != '{"status":"OK","status_det":"OK"}') {
        if (result.type == "messenger") {
          let decodedData = JSON.parse(enc.decrypt(result.data_enc))
          if("message_updates" in decodedData && "chat_updates" in decodedData && !("remove_notifications" in decodedData)){
              if (decodedData.message_updates.length>0) {
                 if(!filter_chats.includes(decodedData.message_updates[0].type) && !filter_message.includes(decodedData.message_updates[0].message.type)){
                     if (filter_chat.length>0) {
                        if (filter_chat.includes(decodedData.message_updates[0].object_guid)) {
                          callback(decodedData);  
                        } 
                     } else {
                       callback(decodedData);  
                     }
              } 
              }else if(decodedData.chat_updates.length>0){
                 if(!filter_chats.includes(decodedData.chat_updates[0].type)){
                callback(decodedData);
              }
              }
          }else if("show_activities" in decodedData){
              if(showActivity){
                  callback(decodedData);
              }
          }else if("remove_notifications" in decodedData){
              callback(decodedData)
          }
        }
      }
    });
    ws.on("error",
      () => {
        console.log(error("connection error...!"))
      })
    ws.on("close",
      () => {
        this.onMessage(callback)
      })
  }
  getChatsUpdates(filter_chats=[],filter_message=[],filter_chat=[]) {
    let date = new Date().getTime() + ""
    let dateArray = []
    for (let num in date) {
      dateArray.push(date[num])
    }
    let statenum = parseInt(dateArray.slice(0, 10).join('')) - 200
    let inData = {
      "method": "getChatsUpdates",
      "input": {
        "state": statenum
      },
      "client": this.client
    }
    let response  = this.errorHandler(inData);
    try {
    let update = response.data.chats
    let mainUpdate = this.updateHandler(update)
    if(mainUpdate){
       if(!filter_chats.includes(mainUpdate.abs_object.type) && !filter_message.includes(mainUpdate.last_message.type)){
           if(filter_chat.length>0){
              if(filter_chat.includes(mainUpdate.object_guid)){
                  return mainUpdate;
              }
           }else{
               return mainUpdate;
           }
       }
    }
    }catch (e) {
        console.log(e)
        return response
    }
  }
  getUserInfoById(username) {
    username = username.split("@")
    username = username[username.length - 1]
    let getGuid = this.getObjectByUsername(username).data.user.user_guid
    let inData = {
      "method": "getUserInfo",
      "input": {
        "user_guid": getGuid
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  getUserInfo(user_guid) {
    let inData = {
      "method": "getUserInfo",
      "input": {
        "user_guid": user_guid
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  getChannelInfo(channel_guid) {
    let inData = {
      "method": "getChannelInfo",
      "input": {
        "channel_guid": channel_guid
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  getChannelInfoByLink(link) {
    let cGuid = this.getLinkFromAppUrl(link).data.link.open_chat_data.object_guid
    let inData = {
      "method": "getChannelInfo",
      "input": {
        "channel_guid": cGuid
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  getChannelInfoById(username) {
    let getGuid;
    if (username.includes("https://") || username.includes("http://")) {
      getGuid = this.getLinkFromAppUrl(username).data.link.open_chat_data.object_guid
    } else {
      username = username.split("@")
      username = username[username.length - 1]
      getGuid = this.getObjectByUsername(username).data.channel.channel_guid
    }
    let inData = {
      "method": "getChannelInfo",
      "input": {
        "channel_guid": getGuid
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  getGroupInfo(group_guid) {
    let inData = {
      "method": "getGroupInfo",
      "input": {
        "group_guid": group_guid
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  getGroupInfoByLink(link) {
    let guidGroup = this.groupPreviewByJoinLink(link).data.group.group_guid
    let inData = {
      "method": "getGroupInfo",
      "input": {
        "group_guid": guidGroup
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  getBlockedUsers(start_id) {
    let inData = {
      "method": "getBlockedUsers",
      "input": {
        "start_id": start_id
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  setBlockUser(user_guid, action) {
    let inData = {
      "method": "setBlockUser",
      "input": {
        "user_guid": user_guid,
        "action": action
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  BlockUser(user_guid) {
    let inData = {
      "method": "setBlockUser",
      "input": {
        "user_guid": user_guid,
        "action": "Block"
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  unBlockUser(user_guid) {
    let inData = {
      "method": "setBlockUser",
      "input": {
        "user_guid": user_guid,
        "action": "Unblock"
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  getMySessions() {
    let inData = {
      "method": "getMySessions",
      "input": {},
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  deleteSession(session_key) {
    let inData = {
      "method": "terminateSession",
      "input": {
        "session_key": session_key
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  deleteOtherSessions() {
    let inData = {
      "method": "terminateOtherSessions",
      "input": {},
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  getLinkFromAppUrl(app_url) {
    let inData = {
      "method": "getLinkFromAppUrl",
      "input": {
        "app_url": app_url
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  getPostInfoByLink(link) {
    let postBaseInfo = this.getLinkFromAppUrl(link).data.link.open_chat_data
    let postAllInfo = this.getMessagesByID(postBaseInfo.object_guid, [postBaseInfo.message_id])
    return {
      ...postAllInfo.data.messages[0],
      timestamp: postAllInfo.data.timestamp
    }
  }
  sendMessage(chat_id, text, message_id) {
    let inData = {
      "method": "sendMessage",
      "input": {
        "object_guid": chat_id,
        "rnd": Math.floor(Math.random() * 999999999),
        "file_inline": null,
        "text": text,
        ...(message_id && {
          "reply_to_message_id": message_id
        })
      },
      "client": this.client

    }
    return this.errorHandler(inData)
  }
  editMessage(object_guid, message_id, text) {
    let inData = {
      "method": "editMessage",
      "input": {
        "object_guid": object_guid,
        "message_id": message_id,
        "text": text
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  localDeleteMessages(object_guid, message_ids) {
    let inData = {
      "method": "deleteMessages",
      "input": {
        "object_guid": object_guid,
        "message_ids": message_ids,
        "type": "Local"
      },
      "client": this.client
    }
  }
  deleteMessages(chat_id, message_ids) {
    let inData = {
      "method": "deleteMessages",
      "input": {
        "object_guid": chat_id,
        "message_ids": message_ids,
        "type": "Global"
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  sendLocation(object_guid, latitude, longitude) {
    let inData = {
      "method": "sendMessage",
      "input": {
        "object_guid": object_guid,
        "rnd": Math.floor(Math.random() * 999999999),
        ...(message_id && {
          "reply_to_message_id": message_id
        }),
        "file_inline": null,
        "location": {
          "latitude": latitude,
          "longitude": longitude
        }
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  forwardMessages(from, to, message_ids) {
    let inData = {
      "method": "forwardMessages",
      "input": {
        "from_object_guid": from,
        "to_object_guid": to,
        "message_ids": message_ids,
        "rnd": Math.floor(Math.random() * 999999999)
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  joinGroup(link) {
    if (link) {
      link = link.split("/")
      link = link[link.length - 1]
      let inData = {
        "method": "joinGroup",
        "input": {
          "hash_link": link
        },
        "client": this.client
      }
      return this.errorHandler(inData)
    }
  }
  leaveGroup(group_guid) {
    let inData = {
      "method": "leaveGroup",
      "input": {
        "group_guid": group_guid
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  groupPreviewByJoinLink(link) {
    link = link.split("/")
    link = link[link.length - 1]
    let inData = {
      "method": "groupPreviewByJoinLink",
      "input": {
        "hash_link": link
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  leaveGroupByLink(link) {
    let guidGroup = this.groupPreviewByJoinLink(link).data.group.group_guid
    let inData = {
      "method": "leaveGroup",
      "input": {
        "group_guid": guidGroup
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  joinChannelByLink(link) {
    link = link.split("/")
    link = link[link.length - 1]
    let inData = {
      "method": "joinChannelByLink",
      "input": {
        "hash_link": link
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  joinChannelAction(channel_guid, action) {
    let inData = {
      "method": "joinChannelAction",
      "input": {
        "channel_guid": channel_guid,
        "action": action
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  joinChannelActionById(
    username, action) {
    let getGuid;
    if (username.includes("https://") || username.includes("http://")) {
      getGuid = this.getLinkFromAppUrl(username).data.link.open_chat_data.object_guid
    } else {
      username = username.split("@")
      username = username[username.length - 1]
      getGuid = this.getObjectByUsername(username).data.channel.channel_guid
    }
    let inData = {
      "method": "joinChannelAction",
      "input": {
        "channel_guid": getGuid,
        "action": action
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  leaveChannel(channel_guid) {
    let inData = {
      "method": "joinChannelAction",
      "input": {
        "channel_guid": channel_guid,
        "action": "Leave"
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  leaveChannelByLink(link) {
    let cGuid = this.getLinkFromAppUrl(link).data.link.open_chat_data.object_guid
    let inData = {
      "method": "joinChannelAction",
      "input": {
        "channel_guid": cGuid,
        "action": "Leave"
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  leaveChannelById(username) {
    let getGuid;
    if (username.includes("https://") || username.includes("http://")) {
      getGuid = this.getLinkFromAppUrl(username).data.link.open_chat_data.object_guid
    } else {
      username = username.split("@")
      username = username[username.length - 1]
      getGuid = this.getObjectByUsername(username).data.channel.channel_guid
    }
    let inData = {
      "method": "joinChannelAction",
      "input": {
        "channel_guid": getGuid,
        "action": "Leave"
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  channelPreviewByJoinLink(link) {
    link = link.split("/")
    link = link[link.length - 1]
    let inData = {
      "method": "joinChannelByLink",
      "input": {
        "hash_link": link
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  joinChannelById(username) {
    let getGuid;
    if (username.includes("https://") || username.includes("http://")) {
      getGuid = this.getLinkFromAppUrl(username).data.link.open_chat_data.object_guid
    } else {
      username = username.split("@")
      username = username[username.length - 1]
      getGuid = this.getObjectByUsername(username).data.channel.channel_guid
    }
    let inData = {
      "method": "joinChannelAction",
      "input": {
        "channel_guid": getGuid,
        "action": "Join"
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  getObjectByUsername(username) {
    username = username.split("@")
    username = username[username.length - 1]
    let inData = {
      "method": "getObjectByUsername",
      "input": {
        "username": username
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  deleteUserChat(user_guid, last_deleted_message_id) {
    let inData = {
      "method": "deleteUserChat",
      "input": {
        "user_guid": user_guid,
        "last_deleted_message_id": last_deleted_message_id
      },
      "client": this.client
    }
    return this.errorHandler(inData)

  }
  requestSendFile(file_path) {
    let mime = file_path.split(".")
    mime = mime[mime.length - 1]
    let file_name = file_path.split("/")
    file_name = file_name[file_name.length - 1]
    const stats = fs.statSync(file_path)
    let file_size = stats.size
    let inData = {
      "method": "requestSendFile",
      "input": {
        "file_name": file_name,
        "size": file_size,
        "mime": mime
      },
      "client": this.client
    }
    return this.errorHandler(inData).data
  }
  uploadFile(file_path) {
    let fileData = this.requestSendFile(file_path)
    let bytef = fs.readFileSync(file_path)
    let id = fileData.id
    let dc_id = fileData.dc_id
    let access_hash_send = fileData.access_hash_send
    let url = fileData.upload_url
    let header = {
      "access-hash-send": access_hash_send,
      "auth": Encryption.changeAuthType(this.auth),
      "file-id": String(id),
      "chunk-size": String(bytef.length),
      "content-type": "application/octet-stream",
      "accept-encoding": "gzip",
      "user-agent": "okhttp/3.12.1"
    }
    if (bytef.length <= 131072) {
      header['part-number'] = '1';
      header['total-part'] = '1';
      header["content-length"] = String(bytef.length);
      while (true) {
        try {
          const response = request("POST", url, {
            headers: header,
            body: bytef
          })
          console.log('\r' + `${success(Math.round(bytef.length / 1024) / 1024)} ${warn("MB")} ${magenta("/")}`, `${success(Math.round(bytef.length / 1024) / 1024)} ${warn("MB")}`);
          console.log(success("Uploaded...!"))
          let result = response.getBody("utf-8")
          result = JSON.parse(result).data.access_hash_rec
          return [fileData,
                        result];
        } catch (error) {
          continue;
        }
      }
    } else {
      const t = Math.floor(bytef.length / 131072) + 1;
      for (let i = 1; i <= t; i++) {
        if (i !== t) {
          const k = (i - 1) * 131072;
          header['chunk-size'] = '131072';
          header['part-number'] = String(i);
          header['total-part'] = String(t);
          let count = 0
          while (true) {
            count++
            try {
              const response = request("POST", url, {
                headers: header,
                body: bytef.slice(k, k + 131072)
              })
              console.log('\r' + `${error(Math.round(k / 1024) / 1024)} ${warn("MB")} ${magenta("/")}`, `${success(Math.round(bytef.length / 1024) / 1024)} ${warn("MB")}`);
              break;
            } catch (error) {
              if (count == 10) {
                console.log(warn("upload error try for upload again...!"))
                count = 0
              }
              continue;
            }
          }
        } else {
          const k = (i - 1) * 131072;
          header['chunk-size'] = String(bytef.slice(k).length);
          header['part-number'] = String(i);
          header['total-part'] = String(t);
          while (true) {
            try {
              const response = request("POST", url, {
                headers: header,
                body: bytef.slice(k)
              })
              console.log('\r' + `${success(Math.round(bytef.length / 1024) / 1024)} ${warn("MB")} ${magenta("/")}`, `${success(Math.round(bytef.length / 1024) / 1024)} ${warn("MB")}`);
              console.log(success("Uploaded...!"))
              let result = response.getBody("utf-8")
              result = JSON.parse(result).data.access_hash_rec
              return [fileData,
                                result];
            } catch (error) {
              continue;
            }
          }
        }
      }
    }
  }
  sendPhoto(object_guid, file_path, caption, reply) {
    let fileNameDownloaded = decodeURI(file_path)
    let uploadData
    let fileName
    if (fileNameDownloaded.includes("http") && fileNameDownloaded.includes("://")) {
      let format = file_path.split(".")
      format = format[format.length - 1]
      fileName = "JsrubiFile." + format
      let response = request("GET", file_path).getBody()
      fs.writeFileSync(fileName, response);
      uploadData = this.uploadFile(fileName)
    } else {
      fileName = file_path
      uploadData = this.uploadFile(file_path)
    }
    let fileData = uploadData[0]
    let ahr = String(uploadData[1])
    let file_id = fileData.id
    let dc_id = fileData.dc_id
    let mime = fileName.split(".")
    mime = mime[mime.length - 1]
    let file_name = fileName
    const stats = fs.statSync(fileName)
    let file_size = stats.size
    let dimensions = sizeOf(fs.readFileSync(fileName));
    let width = dimensions.width
    let height = dimensions.height
    if (file_path.includes("http") && file_path.includes("://")) {
      fs.unlinkSync(fileName)
    }
    let inData = {
      "method": "sendMessage",
      "input": {
        "object_guid": object_guid,
        "rnd": Math.floor(Math.random() * 999999999),
        "file_inline": {
          "dc_id": dc_id,
          "file_id": file_id,
          "type": "Image",
          "file_name": file_name,
          "size": file_size,
          "mime": mime,
          "thumb_inline": "/9j/4AAQSkZJRgABAQAAAQABAAD/4gHYSUNDX1BST0ZJTEUAAQEAAAHIAAAAAAQwAABtbnRyUkdCIFhZWiAAAAAAAAAAAAAAAABhY3NwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAA9tYAAQAAAADTLQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAlkZXNjAAAA8AAAACRyWFlaAAABFAAAABRnWFlaAAABKAAAABRiWFlaAAABPAAAABR3dHB0AAABUAAAABRyVFJDAAABZAAAAChnVFJDAAABZAAAAChiVFJDAAABZAAAAChjcHJ0AAABjAAAADxtbHVjAAAAAAAAAAEAAAAMZW5VUwAAAAgAAAAcAHMAUgBHAEJYWVogAAAAAAAAb6IAADj1AAADkFhZWiAAAAAAAABimQAAt4UAABjaWFlaIAAAAAAAACSgAAAPhAAAts9YWVogAAAAAAAA9tYAAQAAAADTLXBhcmEAAAAAAAQAAAACZmYAAPKnAAANWQAAE9AAAApbAAAAAAAAAABtbHVjAAAAAAAAAAEAAAAMZW5VUwAAACAAAAAcAEcAbwBvAGcAbABlACAASQBuAGMALgAgADIAMAAxADb/2wBDAAMCAgICAgMCAgIDAwMDBAYEBAQEBAgGBgUGCQgKCgkICQkKDA8MCgsOCwkJDRENDg8QEBEQCgwSExIQEw8QEBD/2wBDAQMDAwQDBAgEBAgQCwkLEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBD/wAARCAAoACgDASIAAhEBAxEB/8QAGwAAAgIDAQAAAAAAAAAAAAAAAAYECAUHCQP/xAAtEAACAQMDAwMDAwUAAAAAAAABAgMEBREABiEHEjETQVEUcYEiQmEycpGSsf/EABgBAAMBAQAAAAAAAAAAAAAAAAIDBQEE/8QAIBEAAgICAgIDAAAAAAAAAAAAAAECAxEhEjEEIjJRkf/aAAwDAQACEQMRAD8A6JUzVKv2UtGqDxnJxpc6y7o3Zsnphe9xWCop4blFHHDSyyR96QPI4QSFf3duSce5xrEWLrltS4yJFMZ6INwJJVDJ+SpOP8aaN6Udv3/sC97ahroHF1oJIoZFdTiTGYyD/cF59tQKfTU20/wpS2+tFH+n29Orlq3Gu5711YvdRdZJyyK1UzU0mSCEeN/0sDjBAA4PHjOuh+379T7isVDe6Z0K1cCSMEbuCOQO5PuDkfPGuVVFV2Pb98horrU3Cevo55XaV2YLCpxmJssSe0rznkc5I8avb0H6ubCh6c2eknvMi1k6y1NQhiZhG7yNxkDwQAR99UqLd+wvyaUscTepOSCf2nI0aXl33tOURyQ3+kkVyc9rHI49x5GjXQ7oJ4yjk4T+igcVyq4mJjZgw+DjTXY75uWhplkiu9RTRyjPpI5H5Px+NJtHR1Es8cbJKnewVj6ueM/GNMd5rI6K01tVISqRQMwI9uMD/o0qNMX81lDpWPKUTT+4enlBvTeu4NwruSaENP8AUmGUfokIUCbLjOMkEnwTnn50+9JZlhpK6tVm9RGWkjUIQqRqARgnznIP8YA1hdhWOeuNVcrnOXonIWKISkq5wCxYE+2cY4B+NNW1Lc1mstPb2cMylpXYcdzMSQf9ca2qvLUmgrZ8U4Jj9bNyGlnxIxCyDtJz/T/OjSnJM3romcAqTo0UvHhJ5wKjdOKwQaKoD1MSqoGGB+w1PrZknL0LRI0bqVfvPDgjkYxyPvo0aYAQ4KWmtNu+jt9OkdPDG3pxooAHHgY160bO9JTO6FGaCMsD7HtGRo0aYgX2FWwjKSscYyNGjRoZdmH/2Q==",
          "width": width,
          "height": height,
          "access_hash_rec": ahr
        },
        ...(caption && {
          text: caption
        }),
        ...(reply && {
          reply_to_message_id: reply
        })
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  async sendVoice(object_guid, file_path) {
    let metaInfo = await audioMeta.meta(file_path)
    let duration = metaInfo.duration.durationSecs * 1000
    const stats = fs.statSync(file_path)
    let file_size = stats.size
    let uploadData = this.uploadFile(file_path)
    let fileData = uploadData[0]
    let ahr = String(uploadData[1])
    let file_id = fileData.id
    let dc_id = fileData.dc_id
    let mime = file_path.split(".")
    mime = mime[mime.length - 1]
    let file_name = file_path.split("/")
    file_name = file_name[file_name.length - 1]
    let inData = {
      "method": "sendMessage",
      "input": {
        "object_guid": object_guid,
        "rnd": Math.floor(Math.random() * 999999999),
        "file_inline": {
          "file_name": file_name,
          "time": duration,
          "size": file_size,
          "type": "Voice",
          "dc_id": dc_id,
          "file_id": file_id,
          "mime": mime,
          "access_hash_rec": ahr
        }
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  async sendMusic(object_guid, file_path, caption, reply) {
    let fileName
    let uploadData
    let fileNameDownloaded = decodeURI(file_path).split("/")
    fileNameDownloaded = fileNameDownloaded[fileNameDownloaded.length - 1]
    if (file_path.includes("http") && file_path.includes("://")) {
      fileName = fileNameDownloaded
      let response = request("GET", file_path).getBody()
      fs.writeFileSync(fileNameDownloaded, response);
      uploadData = this.uploadFile(fileNameDownloaded)
    } else {
      fileName = file_path
      uploadData = this.uploadFile(file_path)
    }
    let metaInfo = await audioMeta.meta(fileName)
    let duration = metaInfo.duration.durationSecs
    let artist;
    if (metaInfo.trackInfo.length > 0) {
      artist = metaInfo.trackInfo[0]
    } else if (metaInfo.file.split("-").length > 0) {
      artist = metaInfo.file.split("-")
      artist = artist[0]
    } else {
      artist = metaInfo.file
    }
    const stats = fs.statSync(fileName)
    let file_size = stats.size
    if (file_path.includes("http") && file_path.includes("://")) {
      fs.unlinkSync(fileName)
    }
    let fileData = uploadData[0]
    let ahr = String(uploadData[1])
    let file_id = fileData.id
    let dc_id = fileData.dc_id
    let mime = file_path.split(".")
    mime = mime[mime.length - 1]
    let file_name = fileName.split("/")
    file_name = file_name[file_name.length - 1]
    let inData = {
      "method": "sendMessage",
      "input": {
        "is_mute": false,
        "object_guid": object_guid,
        "rnd": Math.floor(Math.random() * 999999999),
        "file_inline": {
          "file_name": file_name,
          "time": duration,
          "size": file_size,
          "type": "Music",
          "dc_id": dc_id,
          "file_id": file_id,
          "mime": mime,
          "access_hash_rec": ahr,
          "music_performer": artist,
          "is_round": false
        },
        ...(caption && {
          text: caption
        }),
        ...(reply && {
          reply_to_message_id: reply
        })
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  sendVideo(object_guid, file_path, caption, reply) {
    let fileNameDownloaded = decodeURI(file_path)
    let uploadData
    let fileName
    if (fileNameDownloaded.includes("http") && fileNameDownloaded.includes("://")) {
      let format = file_path.split(".")
      format = format[format.length - 1]
      fileName = "JsrubiFile." + format
      let response = request("GET", file_path).getBody()
      fs.writeFileSync(fileName, response);
      uploadData = this.uploadFile(fileName)
    } else {
      fileName = file_path
      uploadData = this.uploadFile(file_path)
    }
    let fileData = uploadData[0]
    let ahr = String(uploadData[1])
    let file_id = fileData.id
    let dc_id = fileData.dc_id
    let mime = fileName.split(".")
    mime = mime[mime.length - 1]
    let file_name = fileName
    const stats = fs.statSync(fileName)
    let file_size = stats.size
    let width = 260
    let height = 260
    if (file_path.includes("http") && file_path.includes("://")) {
      fs.unlinkSync(fileName)
    }
    let inData = {
      "method": "sendMessage",
      "input": {
        "object_guid": object_guid,
        "rnd": Math.floor(Math.random() * 999999999),
        "file_inline": {
          "dc_id": dc_id,
          "file_id": file_id,
          "type": "Video",
          "file_name": file_name,
          "size": file_size,
          "mime": mime,
          "time": 1,
          "thumb_inline": "/9j/4AAQSkZJRgABAQAAAQABAAD/4gHYSUNDX1BST0ZJTEUAAQEAAAHIAAAAAAQwAABtbnRyUkdCIFhZWiAAAAAAAAAAAAAAAABhY3NwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAA9tYAAQAAAADTLQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAlkZXNjAAAA8AAAACRyWFlaAAABFAAAABRnWFlaAAABKAAAABRiWFlaAAABPAAAABR3dHB0AAABUAAAABRyVFJDAAABZAAAAChnVFJDAAABZAAAAChiVFJDAAABZAAAAChjcHJ0AAABjAAAADxtbHVjAAAAAAAAAAEAAAAMZW5VUwAAAAgAAAAcAHMAUgBHAEJYWVogAAAAAAAAb6IAADj1AAADkFhZWiAAAAAAAABimQAAt4UAABjaWFlaIAAAAAAAACSgAAAPhAAAts9YWVogAAAAAAAA9tYAAQAAAADTLXBhcmEAAAAAAAQAAAACZmYAAPKnAAANWQAAE9AAAApbAAAAAAAAAABtbHVjAAAAAAAAAAEAAAAMZW5VUwAAACAAAAAcAEcAbwBvAGcAbABlACAASQBuAGMALgAgADIAMAAxADb/2wBDAAMCAgICAgMCAgIDAwMDBAYEBAQEBAgGBgUGCQgKCgkICQkKDA8MCgsOCwkJDRENDg8QEBEQCgwSExIQEw8QEBD/2wBDAQMDAwQDBAgEBAgQCwkLEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBD/wAARCAAoACgDASIAAhEBAxEB/8QAGwAAAgIDAQAAAAAAAAAAAAAAAAYECAUHCQP/xAAtEAACAQMDAwMDAwUAAAAAAAABAgMEBREABiEHEjETQVEUcYEiQmEycpGSsf/EABgBAAMBAQAAAAAAAAAAAAAAAAIDBQEE/8QAIBEAAgICAgIDAAAAAAAAAAAAAAECAxEhEjEEIjJRkf/aAAwDAQACEQMRAD8A6JUzVKv2UtGqDxnJxpc6y7o3Zsnphe9xWCop4blFHHDSyyR96QPI4QSFf3duSce5xrEWLrltS4yJFMZ6INwJJVDJ+SpOP8aaN6Udv3/sC97ahroHF1oJIoZFdTiTGYyD/cF59tQKfTU20/wpS2+tFH+n29Orlq3Gu5711YvdRdZJyyK1UzU0mSCEeN/0sDjBAA4PHjOuh+379T7isVDe6Z0K1cCSMEbuCOQO5PuDkfPGuVVFV2Pb98horrU3Cevo55XaV2YLCpxmJssSe0rznkc5I8avb0H6ubCh6c2eknvMi1k6y1NQhiZhG7yNxkDwQAR99UqLd+wvyaUscTepOSCf2nI0aXl33tOURyQ3+kkVyc9rHI49x5GjXQ7oJ4yjk4T+igcVyq4mJjZgw+DjTXY75uWhplkiu9RTRyjPpI5H5Px+NJtHR1Es8cbJKnewVj6ueM/GNMd5rI6K01tVISqRQMwI9uMD/o0qNMX81lDpWPKUTT+4enlBvTeu4NwruSaENP8AUmGUfokIUCbLjOMkEnwTnn50+9JZlhpK6tVm9RGWkjUIQqRqARgnznIP8YA1hdhWOeuNVcrnOXonIWKISkq5wCxYE+2cY4B+NNW1Lc1mstPb2cMylpXYcdzMSQf9ca2qvLUmgrZ8U4Jj9bNyGlnxIxCyDtJz/T/OjSnJM3romcAqTo0UvHhJ5wKjdOKwQaKoD1MSqoGGB+w1PrZknL0LRI0bqVfvPDgjkYxyPvo0aYAQ4KWmtNu+jt9OkdPDG3pxooAHHgY160bO9JTO6FGaCMsD7HtGRo0aYgX2FWwjKSscYyNGjRoZdmH/2Q==",
          "width": width,
          "height": height,
          "access_hash_rec": ahr
        },
        ...(caption && {
          text: caption
        }),
        ...(reply && {
          reply_to_message_id: reply
        })
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  sendDocument(object_guid, file_path, caption, reply) {
    let fileNameDownloaded = decodeURI(file_path)
    let uploadData
    let fileName
    if (fileNameDownloaded.includes("http") && fileNameDownloaded.includes("://")) {
      let format = file_path.split(".")
      format = format[format.length - 1]
      fileName = "JsrubiFile." + format
      let response = request("GET", file_path).getBody()
      fs.writeFileSync(fileName, response);
      uploadData = this.uploadFile(fileName)
    } else {
      fileName = file_path
      uploadData = this.uploadFile(file_path)
    }
    let fileData = uploadData[0]
    let ahr = String(uploadData[1])
    let file_id = fileData.id
    let dc_id = fileData.dc_id
    let mime = fileName.split(".")
    mime = mime[mime.length - 1]
    let file_name = fileName
    const stats = fs.statSync(fileName)
    let file_size = stats.size
    if (file_path.includes("http") && file_path.includes("://")) {
      fs.unlinkSync(fileName)
    }
    let inData = {
      "method": "sendMessage",
      "input": {
        "object_guid": object_guid,
        "rnd": Math.floor(Math.random() * 999999999),
        "file_inline": {
          "dc_id": dc_id,
          "file_id": file_id,
          "type": "File",
          "file_name": file_name,
          "size": file_size,
          "mime": mime,
          "access_hash_rec": ahr
        },
        ...(caption && {
          text: caption
        }),
        ...(reply && {
          reply_to_message_id: reply
        })
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  getMyGif(){
      let inData ={"method":"getMyGifSet","input":{},"client":this.client}
      return this.errorHandler(inData)
  }
  addToMyGif(object_guid,message_id){
      let inData = {"method":"addToMyGifSet","input":{"message_id":message_id,"object_guid":object_guid},"client":this.client}
      return this.errorHandler(inData)
  }
   sendGif(object_guid, file_path, caption, reply) {
    let fileNameDownloaded = decodeURI(file_path)
    let uploadData
    let fileName
    if (fileNameDownloaded.includes("http") && fileNameDownloaded.includes("://")) {
      let format = file_path.split(".")
      format = format[format.length - 1]
      fileName = "JsrubiFile." + format
      let response = request("GET", file_path).getBody()
      fs.writeFileSync(fileName, response);
      uploadData = this.uploadFile(fileName)
    } else {
      fileName = file_path
      uploadData = this.uploadFile(file_path)
    }
    let fileData = uploadData[0]
    let ahr = String(uploadData[1])
    let file_id = fileData.id
    let dc_id = fileData.dc_id
    let mime = fileName.split(".")
    mime = mime[mime.length - 1]
    let file_name = fileName
    const stats = fs.statSync(fileName)
    let file_size = stats.size
    if (file_path.includes("http") && file_path.includes("://")) {
      fs.unlinkSync(fileName)
    }
    let inData = {"method":"sendMessage","input":{"object_guid":object_guid,"rnd":Math.floor(Math.random() * 999999999),"file_inline":{"file_id":file_id,"mime":mime,"dc_id":dc_id,"access_hash_rec":ahr,"file_name":file_name,"thumb_inline":"/9j/4AAQSkZJRgABAQAAAQABAAD/4gHYSUNDX1BST0ZJTEUAAQEAAAHIAAAAAAQwAABtbnRyUkdCIFhZWiAAAAAAAAAAAAAAAABhY3NwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAA9tYAAQAAAADTLQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAlkZXNjAAAA8AAAACRyWFlaAAABFAAAABRnWFlaAAABKAAAABRiWFlaAAABPAAAABR3dHB0AAABUAAAABRyVFJDAAABZAAAAChnVFJDAAABZAAAAChiVFJDAAABZAAAAChjcHJ0AAABjAAAADxtbHVjAAAAAAAAAAEAAAAMZW5VUwAAAAgAAAAcAHMAUgBHAEJYWVogAAAAAAAAb6IAADj1AAADkFhZWiAAAAAAAABimQAAt4UAABjaWFlaIAAAAAAAACSgAAAPhAAAts9YWVogAAAAAAAA9tYAAQAAAADTLXBhcmEAAAAAAAQAAAACZmYAAPKnAAANWQAAE9AAAApbAAAAAAAAAABtbHVjAAAAAAAAAAEAAAAMZW5VUwAAACAAAAAcAEcAbwBvAGcAbABlACAASQBuAGMALgAgADIAMAAxADb/2wBDAAMCAgICAgMCAgIDAwMDBAYEBAQEBAgGBgUGCQgKCgkICQkKDA8MCgsOCwkJDRENDg8QEBEQCgwSExIQEw8QEBD/2wBDAQMDAwQDBAgEBAgQCwkLEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBD/wAARCAAoACgDASIAAhEBAxEB/8QAGwAAAgIDAQAAAAAAAAAAAAAAAAYECAUHCQP/xAAtEAACAQMDAwMDAwUAAAAAAAABAgMEBREABiEHEjETQVEUcYEiQmEycpGSsf/EABgBAAMBAQAAAAAAAAAAAAAAAAIDBQEE/8QAIBEAAgICAgIDAAAAAAAAAAAAAAECAxEhEjEEIjJRkf/aAAwDAQACEQMRAD8A6JUzVKv2UtGqDxnJxpc6y7o3Zsnphe9xWCop4blFHHDSyyR96QPI4QSFf3duSce5xrEWLrltS4yJFMZ6INwJJVDJ+SpOP8aaN6Udv3/sC97ahroHF1oJIoZFdTiTGYyD/cF59tQKfTU20/wpS2+tFH+n29Orlq3Gu5711YvdRdZJyyK1UzU0mSCEeN/0sDjBAA4PHjOuh+379T7isVDe6Z0K1cCSMEbuCOQO5PuDkfPGuVVFV2Pb98horrU3Cevo55XaV2YLCpxmJssSe0rznkc5I8avb0H6ubCh6c2eknvMi1k6y1NQhiZhG7yNxkDwQAR99UqLd+wvyaUscTepOSCf2nI0aXl33tOURyQ3+kkVyc9rHI49x5GjXQ7oJ4yjk4T+igcVyq4mJjZgw+DjTXY75uWhplkiu9RTRyjPpI5H5Px+NJtHR1Es8cbJKnewVj6ueM/GNMd5rI6K01tVISqRQMwI9uMD/o0qNMX81lDpWPKUTT+4enlBvTeu4NwruSaENP8AUmGUfokIUCbLjOMkEnwTnn50+9JZlhpK6tVm9RGWkjUIQqRqARgnznIP8YA1hdhWOeuNVcrnOXonIWKISkq5wCxYE+2cY4B+NNW1Lc1mstPb2cMylpXYcdzMSQf9ca2qvLUmgrZ8U4Jj9bNyGlnxIxCyDtJz/T/OjSnJM3romcAqTo0UvHhJ5wKjdOKwQaKoD1MSqoGGB+w1PrZknL0LRI0bqVfvPDgjkYxyPvo0aYAQ4KWmtNu+jt9OkdPDG3pxooAHHgY160bO9JTO6FGaCMsD7HtGRo0aYgX2FWwjKSscYyNGjRoZdmH/2Q==","width":480,"height":480,"time":1,"size":file_size,"type":"Gif"},...(caption && {
          text: caption
        }),
        ...(reply && {
          reply_to_message_id: reply
        })},"client":this.client}
    return this.errorHandler(inData)
  }
  downloadFile(object_guid, message_id, downloadProgress,save_path) {
    let fileInfo
    let byteList = []
    try {
      fileInfo = this.getMessagesByID(object_guid, [message_id]).data.messages[0].file_inline
    } catch (e) {
      console.log(error("the message is not file or not found"))
      return warn("file not found")
    }
    let header;
    let result;
    if (fileInfo.size < 262144) {
      header = {
        'auth': Encryption.changeAuthType(this.auth),
        'file-id': fileInfo.file_id,
        'access-hash-rec': fileInfo.access_hash_rec,
        'client-app-version': '3.1.1',
        'client-platform': 'Android',
        'client-app-name': 'Main',
        'client-package': 'app.rbmain.a'
      }
      let byteToMg= 0
      while (true) {
        try {
          result = request("POST", `https://messenger${fileInfo.dc_id}.iranlms.ir/GetFile.ashx`, {
            headers: header
          })
          byteToMg += result.getBody().length
            if(downloadProgress){
                console.log('\r' + `${error(Math.round(byteToMg / 1024) / 1024)} ${warn("MB")} ${magenta("/")}`, `${success(Math.round(fileInfo.size / 1024) / 1024)} ${warn("MB")}`)
            }
          break;
        } catch (e) {
          console.log(error("download error try for download again"))
          continue
        }
      }
    } else {
      header = {
        'auth': Encryption.changeAuthType(this.auth),
        'file-id': fileInfo.file_id,
        'access-hash-rec': fileInfo.access_hash_rec
      }
      let startIndex = 0;
      let endIndex = 262144;
      let byteToMg = 0;
      for (let i = 0; i < Math.ceil(fileInfo.size / 262144); i++) {
        header["start-index"] = startIndex
        header["last-index"] = endIndex
        startIndex = endIndex + 1;
        endIndex = startIndex + 262143;
        while (true) {
          try {
            result = request("POST", `https://messenger${fileInfo.dc_id}.iranlms.ir/GetFile.ashx`, {
              headers: header
            })
            byteToMg += result.getBody().length
            if (downloadProgress) {
               console.log('\r' + `${error(Math.round(byteToMg / 1024) / 1024)} ${warn("MB")} ${magenta("/")}`, `${success(Math.round(fileInfo.size / 1024) / 1024)} ${warn("MB")}`) 
            }
            break;
          } catch (e) {
            console.log(error("download error try for download again"))
            continue
          }
        }
        byteList.push(result.getBody())
      }
    }
      if (save_path) {
        let savePath = `${save_path}.${fileInfo.mime}`
        let byteToSend = Buffer.concat(byteList)
        try {
          fs.writeFileSync(savePath, byteToSend)
          if(downloadProgress){
             return success("file saved...!") 
          }else{
             return fileInfo.size 
          }
        } catch (e) {
          return error("save error..!")
        }
      } else {
        if(!downloadProgress){
            return fileInfo.size
        }
      }
  }
  downloadAvatar(save_path, avatarNumber, object_guid) {
    if (!avatarNumber) {
      avatarNumber = 0
    }
    let avatarInfo = this.getAvatars().data.avatars
    if (avatarNumber > avatarInfo.length) {
      avatarInfo = avatarInfo[0].main
    } else {
      avatarInfo = avatarInfo[avatarNumber].main
    }
    let header = {
      'auth': Encryption.changeAuthType(this.auth),
      'file-id': avatarInfo.file_id,
      'access-hash-rec': avatarInfo.access_hash_rec,
      'client-app-version': '3.1.1',
      'client-platform': 'Android',
      'client-app-name': 'Main',
      'client-package': 'app.rbmain.a'
    }
    let result;
    while (true) {
      try {
        result = request("POST", `https://messenger${avatarInfo.dc_id}.iranlms.ir/GetFile.ashx`, {
          headers: header
        })
        break;
      } catch (e) {
        return error("download error try for download again")
        continue
      }
    }
    let savePath = `${save_path}.${avatarInfo.mime}`
    try {
      fs.writeFileSync(savePath, result.getBody());
      return success("file saved...!")
    } catch (e) {
      return error("save error..!")
    }
  }
  getMessages(object_guid, max_id, filter_type) {
    let inData = {
      "method": "getMessages",
      "input": {
        "object_guid": object_guid,
        "sort": "FromMax",
        "filter_type": filter_type,
        "max_id": max_id
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  getMessagesInterval(object_guid, middle_message_id, filter_type) {
    let inData = {
      "method": "getMessagesInterval",
      "input": {
        "object_guid": object_guid,
        "middle_message_id": middle_message_id,
        "filter_type": filter_type
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  getMessagesByID(object_guid, message_ids) {
    let inData = {
      "method": "getMessagesByID",
      "input": {
        "object_guid": object_guid,
        "message_ids": message_ids
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  getChats(start_id) {
    let inData = {
      "method": "getChats",
      "input": {
        "start_id": start_id
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  getAvatars(object_guid) {
    let inData = {
      "method": "getAvatars",
      "input": {
        "object_guid": object_guid
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  getCommonGroups(user_guid) {
    let inData = {
      "method": "getCommonGroups",
      "input": {
        "user_guid": user_guid
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  getGroupAllMembers(group_guid, search_text, start_id) {
    let inData = {
      "method": "getGroupAllMembers",
      "input": {
        "group_guid": group_guid,
        "search_text": search_text,
        "start_id": start_id
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  getGroupDefaultAccess(group_guid) {
    let inData = {
      "method": "getGroupDefaultAccess",
      "input": {
        "group_guid": group_guid
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  setGroupDefaultAccess(group_guid, access_list) {
    let inData = {
      "method": "setGroupDefaultAccess",
      "input": {
        "group_guid": group_guid,
        "access_list": access_list
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  setGroupTimer(group_guid, slow_level) {

    let slowLevel = [0,
            10,
            30,
            60,
            300,
            900,
            3600]
    slowLevel = slowLevel[slow_level]
    let inData = {
      "method": "editGroupInfo",
      "input": {
        "group_guid": group_guid,
        "slow_mode": slowLevel,
        "updated_parameters": ["slow_mode"]
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  getGroupLink(group_guid) {
    let inData = {
      "method": "getGroupLink",
      "input": {
        "group_guid": group_guid
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  addGroupMembers(group_guid, member_guids) {
    if (member_guids.length > 25) {
      member_guids.length = 25
    }
    let inData = {
      "method": "addGroupMembers",
      "input": {
        "group_guid": group_guid,
        "member_guids": member_guids
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  banGroupMember(group_guid, member_guid) {
    let inData = {
      "method": "banGroupMember",
      "input": {
        "group_guid": group_guid,
        "member_guid": member_guid,
        "action": "Set"
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  unBanGroupMember(group_guid, member_guid) {
    let inData = {
      "method": "banGroupMember",
      "input": {
        "group_guid": group_guid,
        "member_guid": member_guid,
        "action": "Unset"
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  getBannedGroupMembers(group_guid, search_text, start_id) {
    let inData = {
      "method": "getBannedGroupMembers",
      "input": {
        "group_guid": group_guid,
        "search_text": search_text,
        "start_id": start_id
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  getGroupAdminMembers(group_guid, start_id) {
    let inData = {
      "method": "getGroupAdminMembers",
      "input": {
        "group_guid": group_guid,
        "start_id": start_id
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  setGroupAdmin(group_guid, member_guid, access_list) {
    let inData = {
      "method": "setGroupAdmin",
      "input": {
        "group_guid": group_guid,
        "member_guid": member_guid,
        "action": "SetAdmin",
        "access_list": access_list
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  unsetGroupAdmin() {
    let inData = {
      "method": "setGroupAdmin",
      "input": {
        "group_guid": group_guid,
        "member_guid": member_guid,
        "action": "UnsetAdmin",
        "access_list": access_list
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  getGroupAdminAccessList(group_guid, member_guid) {
    let inData = {
      "method": "getGroupAdminAccessList",
      "input": {
        "group_guid": group_guid,
        "member_guid": member_guid
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  getGroupOnlineCount(group_guid) {
    let inData = {
      "method": "getGroupOnlineCount",
      "input": {
        "group_guid": group_guid
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  ShowChatHistoryForNewMembers(group_guid, status) {
    if (status) {
      status = "Visible"
    } else {
      status = "Hidden"
    }
    let inData = {
      "method": "editGroupInfo",
      "input": {
        "group_guid": group_guid,
        "chat_history_for_new_members": status,
        "updated_parameters": ["chat_history_for_new_members"]
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  showGlassMessage(group_guid, status) {
    if (status) {
      status = true
    } else {
      status = false
    }
    let inData = {
      "method": "editGroupInfo",
      "input": {
        "group_guid": group_guid,
        "event_messages": status,
        "updated_parameters": ["event_messages"]
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  changeGroupLink(group_guid) {
    let inData = {
      "method": "setGroupLink",
      "input": {
        "group_guid": group_guid
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  editGroupInfo(group_guid, title, description) {
    let inData = {
      "method": "editGroupInfo",
      "input": {
        "group_guid": group_guid,
        "title": title,
        "description": description,
        "updated_parameters": ["title",
                    "description"]
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  getContacts(start_id) {
    let inData = {
      "method": "getContacts",
      "input": {
        "start_id": start_id
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  getContactsUpdates(state) {
    let inData = {
      "method": "getContactsUpdates",
      "input": {
        "state": state
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  getContactsLastOnline(user_guids) {
    let inData = {
      "method": "getContactsLastOnline",
      "input": {
        "user_guids": user_guids
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  deleteContact(user_guid) {
    let inData = {
      "method": "deleteContact",
      "input": {
        "user_guid": user_guid
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  changeContactInfo(first_name, last_name, phone) {
    let inData = {
      "method": "addAddressBook",
      "input": {
        "first_name": first_name,
        "last_name": last_name,
        "phone": phone
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  searchGlobalMessages(search_text, start_id = 0) {
    let inData = {
      "method": "searchGlobalMessages",
      "input": {
        "search_text": search_text,
        "type": "Text",
        "start_id": start_id
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  searchGlobalObjects(search_text) {
    let inData = {
      "method": "searchGlobalObjects",
      "input": {
        "search_text": search_text
      },
      "client": this.client
    }
    return this.errorHandler(inData)

  }
  searchChatMessages(object_guid, search_text) {
    let inData = {
      "method": "searchChatMessages",
      "input": {
        "search_text": search_text,
        "type": "Text",
        "object_guid": object_guid
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  updateProfile(first_name, last_name, bio) {
    let inData = {
      "method": "updateProfile",
      "input": {
        "first_name": first_name,
        "last_name": last_name,
        "bio": bio,
        "updated_parameters": ["first_name",
                    "last_name",
                    "bio"]
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  uploadAvatar(file_path, object_guid) {
    let fileNameDownloaded = decodeURI(file_path)
    let uploadData
    let fileName
    if (fileNameDownloaded.includes("http") && fileNameDownloaded.includes("://")) {
      let format = file_path.split(".")
      format = format[format.length - 1]
      fileName = "JsrubiFile." + format
      let response = request("GET", file_path).getBody()
      fs.writeFileSync(fileName, response);
      uploadData = this.uploadFile(fileName)
    } else {
      fileName = file_path
      uploadData = this.uploadFile(file_path)
    }
    if (file_path.includes("http") && file_path.includes("://")) {
      fs.unlinkSync(fileName)
    }
    let fileid = uploadData[0].id
    let inData = {
      "method": "uploadAvatar",
      "input": {
        "object_guid": object_guid,
        "thumbnail_file_id": fileid,
        "main_file_id": fileid
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  deleteAvatar(avatar_id, object_guid) {
    let inData = {
      "method": "deleteAvatar",
      "input": {
        "object_guid": object_guid,
        "avatar_id": avatar_id
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  checkUserUsername(username) {
    let inData = {
      "method": "checkUserUsername",
      "input": {
        "username": username
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  updateUsername(username) {
    let inData = {
      "method": "updateUsername",
      "input": {
        "username": username
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  setPinMessage(object_guid, message_id, action) {
    let inData = {
      "method": "setPinMessage",
      "input": {
        "object_guid": object_guid,
        "message_id": message_id,
        "action": action
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  pinMessage(object_guid, message_id) {
    let inData = {
      "method": "setPinMessage",
      "input": {
        "object_guid": object_guid,
        "message_id": message_id,
        "action": "Pin"
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  unPinMessage(object_guid, message_id) {
    let inData = {
      "method": "setPinMessage",
      "input": {
        "object_guid": object_guid,
        "message_id": message_id,
        "action": "Unpin"
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  logOut() {
    let inData = {
      "method": "logout",
      "input": {},
      "client": this.client
    }
    if (this.checkSession) {
      fs.unlinkSync(this.checkSession)
    }
    return this.errorHandler(inData)
  }
  sendChatActivity(object_guid, activity) {
    activity = activity + ""
    switch (activity) {
      case '1':
        activity = "Typing"
        break;
      case '2':
        activity = "Recording"
        break;
      case '3':
        activity = "Uploading"
        break;
      default:
        activity = "Typing"
    }
    let inData = {
      "method": "sendChatActivity",
      "input": {
        "object_guid": object_guid,
        "activity": activity
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  getAbsObjects(objects_guids) {
    let inData = {
      "method": "getAbsObjects",
      "input": {
        "objects_guids": objects_guids
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  deleteChatHistory(object_guid, last_message_id) {
    let inData = {
      "method": "deleteChatHistory",
      "input": {
        "object_guid": object_guid,
        "last_message_id": last_message_id
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  getChannelLink(channel_guid) {
    let inData = {
      "method": "getChannelLink",
      "input": {
        "channel_guid": channel_guid
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  getChannelAllMembers(channel_guid, start_id, search_text) {
    let inData = {
      "method": "getChannelAllMembers",
      "input": {
        "channel_guid": channel_guid,
        "start_id": start_id,
        "search_text": search_text
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  addChannelMembers(channel_guid, member_guids) {
    if (member_guids.length > 25) {
      member_guids = 25
    }
    let inData = {
      "method": "addChannelMembers",
      "input": {
        "channel_guid": channel_guid,
        "member_guids": member_guids
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  banChannelMember(channel_guid, member_guid) {
    let inData = {
      "method": "banChannelMember",
      "input": {
        "channel_guid": channel_guid,
        "member_guid": member_guid,
        "action": "Set"
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  getBannedChannelMembers(channel_guid, search_text, start_id) {
    let inData = {
      "method": "getBannedChannelMembers",
      "input": {
        "channel_guid": channel_guid,
        "search_text": search_text,
        "start_id": start_id
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  unBanChannelMember(channel_guid, member_guid) {
    let inData = {
      "method": "banChannelMember",
      "input": {
        "channel_guid": channel_guid,
        "member_guid": member_guid,
        "action": "Unset"
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  requestChangeObjectOwner(object_guid, new_owner_user_guid) {
    let inData = {
      "method": "requestChangeObjectOwner",
      "input": {
        "object_guid": object_guid,
        "new_owner_user_guid": new_owner_user_guid
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  getPendingObjectOwner(object_guid) {
    let inData = {
      "method": "getPendingObjectOwner",
      "input": {
        "object_guid": object_guid
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  editChannelInfo(channel_guid, title, description) {
    let inData = {
      "method": "editChannelInfo",
      "input": {
        "channel_guid": channel_guid,
        "title": title,
        "description": description,
        "updated_parameters": ["title",
                        "description"]
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  setChannelLink(channel_guid) {
    let inData = {
      "method": "setChannelLink",
      "input": {
        "channel_guid": channel_guid
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  setTypeChannel(channel_guid, type) {
    type = type + ""
    switch (type) {
      case '0':
        type = "Private"
        break;
      case '1':
        type = "Public"
        break;
      default:
        type = "Private"
    }
    let inData = {
      "method": "editChannelInfo",
      "input": {
        "channel_guid": channel_guid,
        "channel_type": type,
        "updated_parameters": ["channel_type"]
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  updateChannelUsername(channel_guid, username) {
    let inData = {
      "method": "updateChannelUsername",
      "input": {
        "channel_guid": channel_guid,
        "username": username
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  checkChannelUsername(username) {
    let inData = {
      "method": "checkChannelUsername",
      "input": {
        "username": username
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  getChannelAdminMembers(channel_guid, start_id) {
    let inData = {
      "method": "getChannelAdminMembers",
      "input": {
        "channel_guid": channel_guid,
        "start_id": start_id
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  setChannelAdmin(channel_guid, member_guid, access_list) {
    let inData = {
      "method": "setChannelAdmin",
      "input": {
        "channel_guid": channel_guid,
        "member_guid": member_guid,
        "action": "SetAdmin",
        "access_list": access_list
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  unSetChannelAdmin(channel_guid, member_guid) {
    let inData = {
      "method": "setChannelAdmin",
      "input": {
        "channel_guid": channel_guid,
        "member_guid": member_guid,
        "action": "UnsetAdmin"
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  getChannelAdminAccessList(channel_guid, member_guid) {
    let inData = {
      "method": "getChannelAdminAccessList",
      "input": {
        "channel_guid": channel_guid,
        "member_guid": member_guid
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  channelSignMessages(channel_guid, sign_messages) {
    if (sign_messages) {
      sign_messages = true
    } else {
      sign_messages = false
    }
    let inData = {
      "method": "editChannelInfo",
      "input": {
        "channel_guid": channel_guid,
        "sign_messages": sign_messages,
        "updated_parameters": ["sign_messages"]
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  reportObject(object_guid, reportType) {
    let report = [102,
                    101,
                    104,
                    103,
                    105,
                    106]
    if (!reportObject || reportType > 5) {
      reportType = report[0]
    } else {
      reportType = report[reportType]
    }
    let inData = {
      "method": "reportObject",
      "input": {
        "object_guid": object_guid,
        "message_id": null,
        "report_type": reportType,
        "report_type_object": "Object",
        "live_id": null
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  reportObjectMessage(object_guid, message_id, reportType) {
    let report = [102,
                    101,
                    104,
                    103,
                    105,
                    106]
    if (!reportObject || reportType > 5) {
      reportType = report[0]
    } else {
      reportType = report[reportType]
    }
    let inData = {
      "method": "reportObject",
      "input": {
        "object_guid": object_guid,
        "message_id": message_id,
        "report_type": reportType,
        "report_type_object": "Message",
        "live_id": null
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  reportTypeOtherObjectMessage(object_guid, message_id, report_description) {
    let inData = {
      "method": "reportObject",
      "input": {
        "object_guid": object_guid,
        "message_id": message_id,
        "report_type": 100,
        "report_type_object": "Message",
        "live_id": null,
        "report_description": report_description
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  reportTypeOtherObject(object_guid, report_description) {
    let inData = {
      "method": "reportObject",
      "input": {
        "object_guid": object_guid,
        "message_id": null,
        "report_type": 100,
        "report_type_object": "Object",
        "live_id": null,
        "report_description": report_description
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  reportObjectLive(object_guid, message_id, live_id, reportType) {
    let report = [102,
                    101,
                    104,
                    103,
                    105,
                    106]
    if (!reportObject || reportType > 5) {
      reportType = report[0]
    } else {
      reportType = report[reportType]
    }
    let inData = {
      "method": "reportObject",
      "input": {
        "object_guid": object_guid,
        "message_id": message_id,
        "report_type": reportType,
        "report_type_object": "Live",
        "live_id": live_id
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  reportTypeOtherObjectLive(object_guid, message_id, live_id, report_description) {
    let inData = {
      "method": "reportObject",
      "input": {
        "object_guid": object_guid,
        "message_id": message_id,
        "report_type": 100,
        "report_type_object": "Live",
        "live_id": live_id,
        "report_description": report_description
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  createPoll(object_guid, question, options) {
    let inData = {
      "method": "createPoll",
      "input": {
        "object_guid": object_guid,
        "options": options,
        "rnd": Math.floor(Math.random() * 999999999),
        "question": question,
        "type": "Regular",
        "is_anonymous": true,
        "allows_multiple_answers": false
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  votePoll(poll_id, selection_index) {
    let inData = {
      "method": "votePoll",
      "input": {
        "poll_id": poll_id,
        "selection_index": selection_index
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  getPollStatus(poll_id) {
    let inData = {
      "method": "getPollStatus",
      "input": {
        "poll_id": poll_id
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  createGroupVoiceChat(chat_guid) {
    let inData = {
      "method": "createGroupVoiceChat",
      "input": {
        "chat_guid": chat_guid
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  getGroupVoiceChatUpdates(chat_guid, voice_chat_id, start_id) {
    let inData = {
      "method": "getGroupVoiceChatParticipants",
      "input": {
        "chat_guid": chat_guid,
        "voice_chat_id": voice_chat_id,
        "start_id": start_id
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  getGroupVoiceChatUpdates(chat_guid, voice_chat_id) {
    let date = new Date().getTime() + ""
    let dateArray = []
    for (let num in date) {
      dateArray.push(date[num])
    }
    let statenum = parseInt(dateArray.slice(0, 10).join('')) - 200
    let inData = {
      "method": "getGroupVoiceChatUpdates",
      "input": {
        "chat_guid": chat_guid,
        "voice_chat_id": voice_chat_id,
        "state": statenum
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  leaveGroupVoiceChat(chat_guid, voice_chat_id) {
    let inData = {
      "method": "leaveGroupVoiceChat",
      "input": {
        "chat_guid": chat_guid,
        "voice_chat_id": voice_chat_id
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  setGroupVoiceChatSetting(chat_guid, voice_chat_id, status) {
    if (status) {
      status = true
    } else {
      status = false
    }
    let inData = {
      "method": "setGroupVoiceChatSetting",
      "input": {
        "chat_guid": chat_guid,
        "voice_chat_id": voice_chat_id,
        "join_muted": status,
        "updated_parameters": ["join_muted"]
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  changeTitleVoiceChat(chat_guid, voice_chat_id, title) {
    let inData = {
      "method": "setGroupVoiceChatSetting",
      "input": {
        "chat_guid": chat_guid,
        "voice_chat_id": voice_chat_id,
        "title": title,
        "updated_parameters": ["title"]
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  discardGroupVoiceChat(chat_guid, voice_chat_id) {
    let inData = {
      "method": "discardGroupVoiceChat",
      "input": {
        "chat_guid": chat_guid,
        "voice_chat_id": voice_chat_id
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  getDisplayAsInGroupVoiceChat(chat_guid, start_id) {
    let inData = {
      "method": "getDisplayAsInGroupVoiceChat",
      "input": {
        "chat_guid": chat_guid,
        "start_id": start_id
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  getGroupVoiceChat(chat_guid, voice_chat_id) {
    let inData = {
      "method": "getGroupVoiceChat",
      "input": {
        "voice_chat_id": voice_chat_id,
        "chat_guid": chat_guid
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  joinGroupVoiceChat(chat_guid, voice_chat_id, self_object_guid) {
    let inData = {
      "method": "joinGroupVoiceChat",
      "input": {
        "chat_guid": chat_guid,
        "voice_chat_id": voice_chat_id,
        "sdp_offer_data": "v=0\r\no=- 3555525539290983085 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\na=group:BUNDLE 0\r\na=extmap-allow-mixed\r\na=msid-semantic: WMS b924e286-5b89-4f0f-a499-954ee63ab7c9\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111 63 9 0 8 13 110 126\r\nc=IN IP4 0.0.0.0\r\na=rtcp:9 IN IP4 0.0.0.0\r\na=ice-ufrag:RH9D\r\na=ice-pwd:ID8B2nBXj+t8Q953EuoZwpvZ\r\na=ice-options:trickle\r\na=fingerprint:sha-256 78:93:46:84:42:C0:7E:22:35:88:B1:B2:21:71:76:C5:54:C7:BF:7B:B0:B4:FC:0F:8B:B9:23:43:3A:09:1C:90\r\na=setup:actpass\r\na=mid:0\r\na=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level\r\na=extmap:2 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time\r\na=extmap:3 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01\r\na=extmap:4 urn:ietf:params:rtp-hdrext:sdes:mid\r\na=sendrecv\r\na=msid:b924e286-5b89-4f0f-a499-954ee63ab7c9 482d9c16-fe58-4e95-9b92-86aef71a7d8f\r\na=rtcp-mux\r\na=rtpmap:111 opus/48000/2\r\na=rtcp-fb:111 transport-cc\r\na=fmtp:111 minptime=10;useinbandfec=1\r\na=rtpmap:63 red/48000/2\r\na=fmtp:63 111/111\r\na=rtpmap:9 G722/8000\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:8 PCMA/8000\r\na=rtpmap:13 CN/8000\r\na=rtpmap:110 telephone-event/48000\r\na=rtpmap:126 telephone-event/8000\r\na=ssrc:114194620 cname:DljiHai89Xe6MxlX\r\na=ssrc:114194620 msid:b924e286-5b89-4f0f-a499-954ee63ab7c9 482d9c16-fe58-4e95-9b92-86aef71a7d8f\r\n",
        "self_object_guid": self_object_guid
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  setGroupVoiceChatState(chat_guid, voice_chat_id, participant_object_guid, action) {
    if (action) {
      action = "Mute"
    } else {
      action = "Unmute"
    }
    let inData = {
      "method": "setGroupVoiceChatState",
      "input": {
        "chat_guid": chat_guid,
        "voice_chat_id": voice_chat_id,
        "action": action,
        "participant_object_guid": participant_object_guid
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  createChannel(title, description, channel_type, member_guids) {
    let inData = {
      "method": "addChannel",
      "input": {
        "title": title,
        "description": description,
        "channel_type": channel_type,
        "member_guids": member_guids
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  createGroup(title, member_guids) {
    let inData = {
      "method": "addGroup",
      "input": {
        "title": title,
        "member_guids": member_guids
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
  deleteGroup(group_guid) {
    let inData = {
      "method": "deleteNoAccessGroupChat",
      "input": {
        "group_guid": group_guid
      },
      "client": this.client
    }
    return this.errorHandler(inData)
  }
}
module.exports = jsrubi