// Global.
var ERR_KW = "127.100.100.1";
var SUCC_KW = "127.100.100.100";
var SIGNAL_PING = "ping.signal.nxfilter.org";
var NOTOKEN_IP = "192.168.0.100";

//-----------------------------------------------
function str_is_empty(str) {
	return (typeof str == "undefined") || str == null || str == "";
}

//-----------------------------------------------
function str_is_not_empty(str) {
	return !str_is_empty(str);
}

//-----------------------------------------------
function is_valid_ip(ip){
	return ip.search("^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$") > -1;
}

//-----------------------------------------------
function chk_conn_info(){
	var server = $("#server").val();
	var token = $("#token").val();

	if(str_is_not_empty(server) && server.indexOf("/") > -1){
		alert("Invalid server Address!");
		return false;
	}

/*
	if(str_is_empty(token)){
		alert("Login token missing!");
		return false;
	}
*/

	return true;
}

//-----------------------------------------------
function save_conn(){
	if(!chk_conn_info()){
		return;
	}

	var server = $("#server").val();
	var token = $("#token").val();

	var items = {server: server, token: token};
	chrome.storage.sync.set(items, function(){
		// Send message to service worker.
		chrome.runtime.sendMessage({msg: "/CFG"}, function(response){
			alert("New option saved.");
		});
	});
}

//-----------------------------------------------
function load_gui(){
	var keys = ["server", "token"];

	chrome.storage.sync.get(keys, function(items){
		$("#server").val(items.server);
		$("#token").val(items.token);
	});
}

//-----------------------------------------------
function do_test(){
	if(!chk_conn_info()){
		return;
	}

	var server = $("#server").val();
	var token = $("#token").val();

	if(str_is_empty(token)){
		token = NOTOKEN_IP;
	}

	var tgt_url = "http://" + server + "/hxlistener?token=" + token + "&domain=" + SIGNAL_PING;

	fetch(tgt_url)
	.then(function(response){
		if(response.status != 200){
			alert("Connection error!");
			return;
		}

		return response.text();
	})
	.then(function(text){
		if(text == ERR_KW){
			alert("Login error! - " + server);
		}
		else if(text == SUCC_KW){
			alert("Test success!");
		}
		else{
			alert("Unknown error! - " + server);
		}
	})
	.catch(function() {
		alert("Connection error!");
	});
}

//###############################################
$(document).ready(function(){
	// Load values.
	load_gui();

	$("#btn_test_conn").click(function(){
		do_test();
	});

	$("#btn_save_conn").click(function(){
		save_conn();
	});

	$("#token").keyup(function(){
		$(this).val($(this).val().toUpperCase());
	});
});

//-----------------------------------------------
setTimeout(function(){
	$("body").show();
}, 200);
