# jsrubi

به سادگی حساب کاربری خود را در روبیکا اپلیکیشن پیام رسان ایرانی کنترل کنید

> برای ورژن 8 به بالای nodejs

# سلام من محمد افروزه هستم من خواستم برای کاربران پیام رسان روبیکا یک کتابخونه با nodejs بسازم تا بتوانند در اپلیکیشن روبیکا ربات برای مدیریت گروه ، یا برای انجام کاری بسازم . و خوشبختانه توانستم با اتصال به api روبیکا این کار را انجام دهم

## Installation

    npm install jsrubi

## Usage


```js
let jsrubi = require('jsrubi');
let bot = jsrubi(session)
//or
let bot = jsrubi(auth,key)
```


مثال ها

* example


```js
let jsrubi = require('jsrubi');
let bot = jsrubi(session) /*or*/ jsrubi(auth,key)
bot.sendMessage(chat_id,text)
```

* get update 1
* این روش برای زمانی است که بسته اینترنتی دارید


```js
let jsrubi = require('jsrubi');
let bot = jsrubi(session) /*or*/ jsrubi(auth,key)
bot.onMessage((update)=>{
    console.log(update)
},showActivity(bool),removeGlobalMessage(bool),[chatTypeFilter],[messageTypeFilter],[chatFilter guid chat])
```

* get update 2
* این روش برای زمانی است که بسته اینترنتی ندارید ولی این روش زیاد خوب نیست


```js
let jsrubi = require('jsrubi');
let bot = jsrubi(session) /*or*/ jsrubi(auth,key)
while(true){
    let update = bot.getChatsUpdates([chatTypeFilter],[MessageTypeFilter],[chatFilter guid chat])
    if(update){
       console.log(update) 
    }
}
```


**ایدی من در روبیکا جهت ارتباط با من :**


```
 @TechCode
```


**برای دریافت راهنمایی بیشتر درباره همه ی متد ها رو راهنمایی های کامل به این کانال در روبیکا مراجعه کنید:**



[📚Documentation jsrubi](https://rubika.ir/docsJsrubi)


**برای اطلاع از اخبار کتابخونه به این کانال در روبیکا مراجعه کنید :**



[channel jsrubi](https://rubika.ir/JsRubiLib)



**برای مشاهده مثال ها به این کانال در روبیکا مراجعه کنید :**



[examples jsrubi](https://rubika.ir/jsrubiexamples)
