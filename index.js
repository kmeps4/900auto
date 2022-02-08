var payloadData = "";
sessionStorage.setItem("plrunmethod","");
localStorage.setItem("ipaddress","127.0.0.1");


	//Function to 'get' the payload file.	
	var getPayload=function(payload,onLoadEndCallback){
		var req=new XMLHttpRequest();
		req.open('GET',payload);
		req.send();
		req.responseType="arraybuffer";
		req.onload=function(event){
			if(onLoadEndCallback)onLoadEndCallback(req,event);
		};
	};
	
	//Function to 'send' the payload file to the BinLoader server. 
	var sendPayload=function(url,data,onLoadEndCallback){
		var req=new XMLHttpRequest();
		req.open("POST",url,true);
		req.send(data);
		req.onload=function(event){
			if(onLoadEndCallback)onLoadEndCallback(req,event);
		};
	};

  function checkserverstatus(){
	var req = new XMLHttpRequest(); 
	req.open("POST", "http://"+localStorage.ipaddress+":9090/status");
	req.send();
	req.onerror = function(){
		msgs.innerHTML="<h1 style='font-size:25px;text-align:center;'>GoldHen Bin Server Not Detected, Payloads Will Run Via Host!!!</h1>";
		sessionStorage.plrunmethod = "sandboxesc";
		return;
	};
	req.onload = function(){
	var responseJson = JSON.parse(req.responseText);
	if (responseJson.status=="ready"){
		msgs.innerHTML="<h1 style='font-size:25px;text-align:center;'>GoldHen Bin Server Detected, Payloads Will Run Via Port 9090!!!</h1>";
		sessionStorage.plrunmethod = "ghen20binserver";
		return;
		}
	};
}

//Payloads to be loaded over SandBox Escape using ChendoChap Buffer Array Style
function loadPayloadData() // preload payload data
{
	if (PLfile)
	{
        
        var xhr = new XMLHttpRequest();
        xhr.open('GET', PLfile, true);
        xhr.overrideMimeType('text/plain; charset=x-user-defined');
        xhr.onload = function(e) {
        if (this.status == 200) {
            payloadData = this.response;
            setTimeout(poc, 1500);
        }
        else
        {
			alert("Failed to load " + PLfile + " - " + this.status);
      return;
        }};
        xhr.send();
        
	}
}

function wk_keep_alive()
{
    var xhr = new XMLHttpRequest();
    xhr.open('GET', document.location.href, false);
    xhr.send('');
}
function print(){}

function getScript(source,callback){var gs=document.createElement('script');gs.src=source;gs.onload=callback;gs.async=false;document.body.appendChild(gs);}
function loadScript(name)
{
	getScript(name,function(){});
}

//Payloads to be loaded over SandBox Escape using Sleirsgoevy Style
function loadPayloadDataSleirs(pl) // preload payload data
{
    
	setTimeout(loadScript("netcat.js")
	+loadScript("malloc.js")
	+loadScript("rop_sleirs.js")
	+loadScript("syscalls.js")
	+loadScript("syscalls2.js")
	+loadScript(pl)
	+loadScript("mira.js")
	+loadScript("relocator.js"),1500);
	pldone();
}

  //Payloads to be loaded over GoldHEN Bin Server method
  function LoadpaylodsGhen20(PLfile){ //Loading Payload via Payload Param.
	   // First do an initial check to see if the BinLoader server is running, ready or busy.
	   var req = new XMLHttpRequest(); 
	   req.open("POST", "http://"+localStorage.ipaddress+":9090/status");
	   req.send();
	   req.onerror = function(){
		   alert("Cannot Load Payload Because The BinLoader Server Is Not Running");//<<If server is not running, alert message.
		   return;
	   };
		req.onload = function(){
			var responseJson = JSON.parse(req.responseText);
			if (responseJson.status=="ready"){
		    getPayload(PLfile, function (req) {
				if ((req.status === 200 || req.status === 304) && req.response) {
				   //Sending bins via IP POST Method
					sendPayload("http://" + localStorage.ipaddress + ":9090", req.response, function (req) {
					   if (req.status === 200) {
						pldone();
					   }else{msgs.innerHTML = 'Cannot send payload';return;}
					})
				}
			});
			}
			else {
				alert("Cannot Load Payload Because The BinLoader Server Is Busy");//<<If server is busy, alert message.
				return;
			}
		};
	}

	function loadPayloadauto(){
		if (PLfile)
		{
			
			var xhr = new XMLHttpRequest();
			xhr.open('GET', PLfile, true);
			xhr.overrideMimeType('text/plain; charset=x-user-defined');
			xhr.onload = function(e) {
			if (this.status == 200) {
				payloadData = this.response;
				injectPayload();
				pldone();
			}
			else
			{
				alert("Failed to load " + PLfile + " - " + this.status);
		  return;
			}};
			xhr.send();
			
		}
	   }
	
	function injectPayload() //dynamic payload inject - stooged
	{
		if (payloadData.length > 0)
		{
		   var payload_buffer = chain.syscall(477, 0x0, 0x300000, 0x7, 0x1000, 0xFFFFFFFF, 0);
		   var bufLen = payloadData.length;
		   var payload_loader = p.malloc32(bufLen);
		   var loader_writer = payload_loader.backing;
		   for(var i=0;i<bufLen/4;i++){
				var hxVal = payloadData.slice(i*4,4+(i*4)).split("").reverse().join("").split("").map(function(s){return("0000" + s.charCodeAt(0).toString(16)).slice(-2);}).join("");
				loader_writer[i] = parseInt(hxVal, 16);
		   }
		   chain.syscall(74, payload_loader, 0x4000, (0x1 | 0x2 | 0x4));
		   var pthread = p.malloc(0x10);
		   {
			   chain.fcall(window.syscalls[203], payload_buffer, 0x300000);
			   chain.fcall(libKernelBase.add32(OFFSET_lk_pthread_create), pthread, 0x0, payload_loader, payload_buffer);
		   }
		   chain.run();
		   
		}
		else
		{
		   alert("No Payload Data!");
		}
	}
