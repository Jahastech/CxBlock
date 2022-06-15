//-----------------------------------------------
// Global.
var DEFAULT_CACHE_TTL = 60;
var QUERY_TIMEOUT = 6;
var ERR_KW = "127.100.100.1";
var SUCC_KW = "127.100.100.100";
var SIGNAL_PROXYLOG = "proxylog.signal.nxfilter.org";
var SIGNAL_PING = "ping.signal.nxfilter.org";
var SIGNAL_START = "start.signal.nxfilter.org";
var NOTOKEN_IP = "192.168.0.100";

var cfg = new Config();
var log = new NxLog();
var nxp = new NxPolicy();

var g_debug_flag = true;
var g_domain_cache = {};
var g_uname = "";

var g_start_page = "";
var g_tab_id = 0;  // Not used.

var g_policy_conn_flag = false;
var g_policy_update_cnt = 0

// For block_ip.
var BLOCKIP_URL = "https://redip.nxfilter.org/redip.php?action=get";
var g_block_ip = "";

//###############################################
// Function.
String.prototype.format = function(){
	var formatted = this;
	for(var i = 0; i < arguments.length; i++){
		var regexp = new RegExp('\\{'+i+'\\}', 'gi');
		formatted = formatted.replace(regexp, arguments[i]);
	}
	return formatted;
};

//-----------------------------------------------
function str_is_empty(str) {
	return (typeof str == "undefined") || str == null || str == "";
}

//-----------------------------------------------
function str_is_not_empty(str) {
	return !str_is_empty(str);
}

//-----------------------------------------------
function str_starts_with(str, prefix) {
    return str.indexOf(prefix) == 0;
}

//-----------------------------------------------
function str_ends_with(str, suffix) {
    return str.indexOf(suffix, str.length - suffix.length) !== -1;
}

//-----------------------------------------------
function null2str(obj) {
	if(typeof obj == "undefined"){
		return "";
	}
	return obj == null ? "" : obj;
}

//-----------------------------------------------
function null2bool(obj) {
	if(typeof obj == "undefined"){
		return false;
	}
	return obj == null ? false : obj;
}

//-----------------------------------------------
function get_date14_win(){
	var d = new Date();

	var yyyy = d.getFullYear();
	
	var mm = d.getMonth() + 1;
	if(mm < 10){
		mm = "0" + mm;
	}

	var dd = d.getDate();
	if(dd < 10){
		dd = "0" + dd;
	}

	var hh = d.getHours();
	if(hh < 10){
		hh = "0" + hh;
	}

	var mi = d.getMinutes();
	if(mi < 10){
		mi = "0" + mi;
	}

	var ss = d.getSeconds();
	if(ss < 10){
		ss = "0" + ss;
	}

	return yyyy + "/" + mm + "/" + dd + " " + hh + ":" + mi + ":" + ss;
}

//-----------------------------------------------
function get_date10_win(){
	var d = new Date();

	var yyyy = d.getFullYear();
	
	var mm = d.getMonth() + 1;
	if(mm < 10){
		mm = "0" + mm;
	}

	var dd = d.getDate();
	if(dd < 10){
		dd = "0" + dd;
	}

	var hh = d.getHours();
	if(hh < 10){
		hh = "0" + hh;
	}

	var mi = d.getMinutes();
	if(mi < 10){
		mi = "0" + mi;
	}

	var ss = d.getSeconds();
	if(ss < 10){
		ss = "0" + ss;
	}

	return mm + "/" + dd + " " + hh + ":" + mi + ":" + ss;
}

//-----------------------------------------------
function get_date_hhmm(){
	var d = new Date();

	var hh = d.getHours();
	if(hh < 10){
		hh = "0" + hh;
	}

	var mi = d.getMinutes();
	if(mi < 10){
		mi = "0" + mi;
	}

	return hh + "" + mi;
}

//-----------------------------------------------
function get_location(href) {
	var location = document.createElement("a");
	location.href = href;

	if (str_is_empty(location.host)) {
		location.href = location.href;
	}
	return location;
}

//-----------------------------------------------
function ip2long(ip_address){
	var output = false;
	var parts = [];
	if (ip_address.match(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/)){
		parts = ip_address.split('.');
		output = ( parts[0] * 16777216 +
		(parts[1] * 65536) +
		(parts[2] * 256) +
		(parts[3] * 1 ));
	}
	return output;  
}

//-----------------------------------------------
function is_private_ip(ip){
	if(str_starts_with(ip, "192.168.") || str_starts_with(ip, "10.")){
		return true;
	}
	var ip_long = ip2long(ip);
	return ip_long >= ip2long("172.16.0.0") && ip_long <= ip2long("172.31.255.255");
}

//-----------------------------------------------
function is_valid_ip(ip){
	return ip.search("^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$") > -1;
}

//-----------------------------------------------
function is_valid_domain(line){
	var arr = line.split(/\s+/);
	for(var i = 0; i < arr.length; i++){
		if(arr[i].search(/\.\w{2,}$/) == -1){
			return false;
		}
	}
	return true;
}

//-----------------------------------------------
function hx_lookup(domain){
	if(str_is_empty(cfg.get_hx_url()) || str_is_empty(cfg.get_token())){
		log.error("hx_lookup, Invalid hx_url or no token!");
		return;
	}

	var tgt_url = cfg.get_hx_url() + "?token=" + cfg.get_token() + "&domain=" + domain + "&uname=" + g_uname;
	log.debug("hx_lookup, tgt_url = " + tgt_url);

	fetch(tgt_url)
	.then(function(response){
		return response.text();
	})
	.then(function(text){
		log.debug("hx_lookup, domain = " + domain + ", text = " + text);

		if(text == "/BLOCK"){
			add_domain_cache(domain, true);

			if(!nxp.log_only){
				redi_block_url(domain);
			}
		}
		else{
			add_domain_cache(domain, false);
		}
	})
	.catch(function() {
		log.error("hx_lookup, Connection error!");
	});
}

//-----------------------------------------------
function get_line_num(){
	let e = new Error();
	e = e.stack.split("\n")[2].split(":");
	e.pop();
	return e.pop();
}

//-----------------------------------------------
function unix_timestamp(){
	return Math.round(new Date().getTime() / 1000);
}

//-----------------------------------------------
function add_domain_cache(domain, block_flag){
	var dd = {};
	dd.domain = domain;
	dd.block_flag = block_flag;
	dd.timestamp = unix_timestamp();

	g_domain_cache[domain] = dd;
}

//-----------------------------------------------
function get_cached_domain(domain){
	var dd = g_domain_cache[domain];
	if(dd != null && parseInt(dd.timestamp) >= unix_timestamp() - nxp.cache_ttl){
		return dd;
	}
	return null;
}

//-----------------------------------------------
function is_blocked_domain(domain){
	if(str_is_empty(domain)){
		return false;
	}

	var dd = get_cached_domain(domain);
	if(dd == null){
		hx_lookup(domain);
		return false;
	}

	log.debug("Found cache for " + domain + ", " + dd.block_flag);
	return dd.block_flag;
}

//-----------------------------------------------
function redi_new_url(url){
	//log.debug("g_tab_id, " + g_tab_id);
	log.debug("redi_new_url, " + url);
	/*
	if(g_tab_id == null || g_tab_id <= 0){
		chrome.tabs.update({url: url});
		return;
	}
	*/

	setTimeout(function(){
		chrome.tabs.update({url: url});
	}, 150);

	//chrome.tabs.update({url: url});
//	chrome.tabs.update(g_tab_id, {url: url});
}

//-----------------------------------------------
function redi_block_url(domain){
	var block_url = cfg.get_block_url();

	domain = domain.replace(/^https?\:\/\/|\/.*$/g, "");

	if(str_is_not_empty(block_url)){
		redi_new_url(block_url + "?domain=" + domain);
	}
}

//-----------------------------------------------
function update_policy(useOldFlag){
	// From old data.
	if(useOldFlag){
		var keys = ["policy_text"];

		chrome.storage.sync.get(keys, function(items){
			var policy_text = null2str(items.policy_text);
			//log.debug("update_policy, old data = " + policy_text);
			if(str_is_not_empty(policy_text)){
				log.info("update_policy, We will use old data for a while.");
				nxp.parse_text(policy_text);
				nxp.print();
			}
		});
		return;
	}

	if(str_is_empty(cfg.get_hx_url()) || str_is_empty(cfg.get_token())){
		log.error("hx_update_policy, Invalid hx_url or no token!");
		return;
	}

	log.debug("hx_update_policy, token = " + cfg.get_token());

	var tgt_url = cfg.get_hx_url() + "?action=/CBK&token=" + cfg.get_token();

	// We do it only once in 5 minutes.
	if(g_policy_conn_flag && ++g_policy_update_cnt % 5 != 0){
		return;
	}

	fetch(tgt_url)
	.then(function(response){
		return response.text();
	})
	.then(function(text){
		if(str_is_not_empty(text) && text.indexOf("127.") != 0){
			log.debug("update_policy, " + text);
			nxp.parse_text(text);

			// Save options.
			var items = {policy_text: text};
			chrome.storage.sync.set(items, function(){
				log.info("update_policy, Policy text saved.");
				g_policy_conn_flag = true;
			});
		}
	})
	.catch(function() {
		log.error("update_policy, Connection error!");
	});
}

//-----------------------------------------------
function has_list_domain(list, domain){
	domain = domain.toLowerCase();
	for(var i = 0; i < list.length; i++){
		var temp = list[i];

		if(str_starts_with(temp, "*.")){
			// Exact matching first.
			if(temp == "*." + domain){
				log.debug("domain : " + domain);
				return true;
			}

			// Ends with.
			if(str_ends_with(domain, temp.substring(1))){
				log.debug("domain : " + domain);
				return true;
			}
		}
		else{
			if(temp == domain){
				log.debug("domain : " + domain);
				return true;
			}
		}
	}

	return false;
}

//###############################################
// Config.
function Config(){
	this.server = "";
	this.token = "";
	this.hx_url = "";
	this.block_url = "";

	this.load_time = 0;

	// Binding this to self.
	var self = this;

	//-----------------------------------------------
	this.load = function(){
		var keys = ["server", "token"];

		chrome.storage.sync.get(keys, function(items){
			self.server = null2str(items.server);
			self.token = null2str(items.token);

			if(str_is_empty(self.server)){
				self.hx_url = "";
				self.block_url = "";
				g_block_ip = "";
			}
			else{
				self.hx_url = "http://" + self.server + "/hxlistener";
				self.block_url = "http://" + self.server + "/block,chrome.jsp";
				g_block_ip = self.server;
			}

			self.print();
		});

		this.load_time = unix_timestamp();
	};

	//-----------------------------------------------
	this.is_valid = function(){
		return str_is_not_empty(this.server) && str_is_not_empty(this.token);
	};

	//-----------------------------------------------
	this.get_hx_url = function(){
		return this.hx_url;
	};
	
	//-----------------------------------------------
	this.get_block_url = function(){
		return this.block_url;
	};
	
	//-----------------------------------------------
	this.get_token = function(){
		if(str_is_not_empty(this.hx_url) && is_private_ip(this.server) && str_is_empty(this.token)){
			return NOTOKEN_IP;
		}

		return this.token;
	};
	
	//-----------------------------------------------
	this.save = function(server, token){
		var items = {server: server, token: token};
		chrome.storage.sync.set(items, function(){
			log.info("Config.save, New option saved.");
		});
	};

	//-----------------------------------------------
	this.print = function(){
		log.debug("Config.server = " + this.server);
		log.debug("Config.token = " + this.token);
		log.debug("Config.hx_url = " + this.hx_url);
		log.debug("Config.block_url = " + this.block_url);
	};
}

//-----------------------------------------------
function set_block_ip(){
	if(str_is_not_empty(g_block_ip)){
		log.info("set_block_ip, We already have g_block_ip = " + g_block_ip);
		return;
	}

	fetch(BLOCKIP_URL)
	.then(function(response){
		return response.text();
	})
	.then(function(text){
		if(is_valid_ip(text)){
			g_block_ip = text;
			log.info("set_block_ip, By remote lookup, g_block_ip = " + g_block_ip);

			// Save options.
			var items = {server: g_block_ip};
			chrome.storage.sync.set(items, function(){
				log.info("save_block_ip, New option saved.");
			});

			// Unlike CxForward, we load it again.
			cfg.load();
		}
	})
	.catch(function() {
		log.error("set_block_ip, Connection error!");
	});
}

//-----------------------------------------------
// NxLog.
function NxLog(){

	//-----------------------------------------------
	this.debug = function(line){
		if(!g_debug_flag){
			return;
		}
		console.log("DEBUG [{0}] {1}".format(get_date10_win(), line));
	};

	//-----------------------------------------------
	this.info = function(line){
		console.log("INFO [{0}] {1}".format(get_date10_win(), line));
	};

	//-----------------------------------------------
	this.error = function(line){
		console.log("ERROR [{0}] {1}".format(get_date10_win(), line));
	};

	//-----------------------------------------------
	this.send_proxy_log = function(host, reason){
		// We don't allow dot and '*' in reason.
		reason = reason.replace(/[\!\@\#\$\%\^\&\*\)\(\+\.\<\>\{\}\[\]\:\;\'\"\|\~\`\_\-\\]/g, "_");
		reason = reason.replace(/_+/g, "_");
		reason = reason.replace(/^_|_$/g, "");
		reason = encodeURI(reason);

		line = host + "." + reason + ".proxy." + SIGNAL_PROXYLOG;
		hx_lookup(line);
	};
}

//-----------------------------------------------
// NxPolicy.
function NxPolicy(){
	this.enable_filter = true;
	this.log_only = false;
	this.cloud_flag = false;
	this.url_kw_list = [];

	this.bf_domain_list = [];
	this.system_domain_list = [];
	this.cache_ttl = DEFAULT_CACHE_TTL;

	//-----------------------------------------------
	this.print = function(){
		log.debug("NxPolicy.enable_filter = " + this.enable_filter);
		log.debug("NxPolicy.log_only = " + this.log_only);
		log.debug("NxPolicy.cloud_flag = " + this.cloud_flag);
		log.debug("NxPolicy.url_kw_list = " + this.url_kw_list);

		log.debug("NxPolicy.bf_domain_list = " + this.bf_domain_list);
		log.debug("NxPolicy.system_domain_list = " + this.system_domain_list);
		log.debug("NxPolicy.cache_ttl = " + this.cache_ttl);
	};

	//-----------------------------------------------
	this.parse_text = function(text){
		var _enable_filter = false;
		var _log_only = false;
		var _cloud_flag = false;
		var _url_kw_list = [];

		var _bf_domain_list = [];
		var _system_domain_list = [];
		var _cache_ttl = 0;

		var list = text.split(/\s+/);
		for(var i = 0; i < list.length; i++){
			var kw = list[i];

			if(kw == "-ef"){
				_enable_filter = true;
			}

			if(kw == "-df"){
				_enable_filter = false;
			}

			if(kw == "-lo"){
				_log_only = true;
			}

			if(kw == "-cl"){
				_cloud_flag = true;
			}

			// Blocked keyword.
			if(str_starts_with(kw, "bk:")){
				kw = kw.substring(3);
				var arr = kw.split(";");
				for(var k = 0; k < arr.length; k++){
					var kw = arr[k];
					if(str_is_empty(kw) || kw.length < 2){
						continue;
					}
					_url_kw_list.push(kw);
				}
			}

			// Whitelist domain.
			if(str_starts_with(kw, "fd:")){
				kw = kw.substring(3);
				_bf_domain_list = kw.split(",");
			}

			// Whitelist domain.
			if(str_starts_with(kw, "sd:")){
				kw = kw.substring(3);
				_system_domain_list = kw.split(",");
			}

			// cache_ttl.
			if(str_starts_with(kw, "ct:")){
				_cache_ttl = kw.substring(3);
			}
		}

		// Set policy.
		this.enable_filter = _enable_filter;
		this.log_only = _log_only;
		this.cloud_flag = _cloud_flag;
		this.url_kw_list = _url_kw_list;

		this.bf_domain_list = _bf_domain_list;
		this.system_domain_list = _system_domain_list;
		this.cache_ttl = _cache_ttl;
	};

	//-----------------------------------------------
	this.is_bf_domain = function(domain){
		return has_list_domain(this.system_domain_list, domain) || has_list_domain(this.bf_domain_list, domain);
	};

	//-----------------------------------------------
	this.chk_blocked_kw_for_url = function(url){
		url = decodeURI(url);
		url = url.toLowerCase();
		for(var i = 0; i < this.url_kw_list.length; i++){
			var kw = this.url_kw_list[i];
			if(url.indexOf(kw) > -1){
				return kw;
			}

			if(kw.indexOf("/") == 0 && kw.slice(-1) == "/"){
				kw = kw.replace(/^\/|\/$/g, "");
				if(kw.length >= 2 && url.search(new RegExp(kw)) > -1){
					log.debug("NxPolicy.chk_blocked_kw_for_url, Keyword found = " + kw);
					return kw;
				}
			}
		}

		return "";
	};
}

//-----------------------------------------------
function parse_start_page(){
	log.debug("parse_start_page.");
	if(str_is_empty(g_start_page) || !str_starts_with(g_start_page, "http")){
		log.info("parse_start_page, We don't have a start_page!");
		return;
	}

	var tgt_url = g_start_page;
	if(tgt_url.indexOf("?") > -1){
		tgt_url += "&" + unix_timestamp();
	}
	else{
		tgt_url += "?" + unix_timestamp();
	}

	fetch(tgt_url)
	.then(function(response){
		return response.text();
	})
	.then(function(text){
		var lines = text.split(/\n/);
		for(var i = 0; i < lines.length; i++){
			var line = lines[i];
			if(line.indexOf("<body") > -1 || line.indexOf("<BODY") > -1){
				break;
			}

			if(line.indexOf("<meta") > -1 && line.indexOf("cxblock") > -1){
				line = line.replace(/^.+content/, "");
				line = line.replace(/\s+/g, "");
				line = line.replace(/[='"\/>]/g, "");

				log.debug("parse_start_page, parsed line = " + line);

				log.debug(line);
				var arr = line.split(/:/);
				if(arr.length < 2){
					log.error("parse_start_page, Invalid meta tag!");
					return;
				}

				var server = arr[0];
				var token = arr[1];

				if(str_is_empty(server) || server.indexOf("/") > -1 || !is_valid_ip(server)){
					log.error("parse_start_page, Invalid IP!");
					return;
				}

				// Save options.
				cfg.save(server, token);
				cfg.load();

				return;
			}
		}
	})
	.catch(function() {
		log.error("update_policy, Connection error!");
	});
}

//###############################################
chrome.tabs.query({currentWindow: true, active: true}, function(tabs){
	if(str_is_empty(g_start_page) && tabs[0] != null){
		g_start_page = tabs[0].url;
		log.debug("g_start_page = " + g_start_page);
		parse_start_page();
	}
});

//-----------------------------------------------
chrome.webNavigation.onBeforeNavigate.addListener(function(details){
	// Only top domain.
	if(details.frameId > 0){
		return;
	}

	// Set g_tab_id.
	g_tab_id = details.tabId;

	// We filter only http or https.
	if(!str_starts_with(details.url, "http:") && !str_starts_with(details.url, "https:")){
		return;
	}

	log.debug("onBeforeNavigate, Filtering for : " + details.url);

	// Get host.
	var host = new URL(details.url).hostname;

	// Checking bypass condition.
	if(!nxp.enable_filter){
		log.debug("onBeforeNavigate, Proxy not enabled! - " + nxp.enable_filter);
		return;
	}

	// Bypass these first.
	if(host.indexOf(".") == -1
		|| host == cfg.server
		|| str_starts_with(host, "127.")
		){

		return;
	}

	if(is_private_ip(host)){
		log.info("onBeforeNavigate, Private IP : " + host);
		return;
	}

	if(nxp.is_bf_domain(host)){
		log.info("onBeforeNavigate, Bypassed domain : " + host);
		return;
	}

	kw = nxp.chk_blocked_kw_for_url(details.url);
	if(str_is_not_empty(kw)){
		log.info("onBeforeNavigate, Blocked URL by keyword : " + details.url);
		log.send_proxy_log(host, "url_kw=" + kw);
		
		if(!nxp.log_only){
			redi_block_url(host);
		}
		
		return;
	}

	if(is_blocked_domain(host)){
		log.info("onBeforeNavigate, Blocked! - " + host);

		if(!nxp.log_only){
			redi_block_url(details.url);
		}
	}
});

//-----------------------------------------------
chrome.identity.getProfileUserInfo(function(userInfo){
	g_uname = userInfo.email.replace(/@.*$/, "");
	log.info("getProfileUserInfo, g_uname = " + g_uname);
});

//-----------------------------------------------
chrome.runtime.onMessage.addListener(
	function(request, sender, sendResponse){
		if (request.msg === "/CFG"){
			cfg.load();
		}
		sendResponse("whatever");
	}
);

//-----------------------------------------------
// Main.
log.info("Init..");
cfg.load();

setTimeout(function(){
	set_block_ip();
}, 1000 * 3);

// Signal.
setTimeout(function(){
	hx_lookup(SIGNAL_START);
}, 1000 * 5);

/*
setInterval(function(){
	hx_lookup(SIGNAL_PING);
}, 1000 * 60);
*/

setInterval(function(){
	try{
		hx_lookup(SIGNAL_PING);
	}
	catch(err){
		log.info(err.message);
	}
}, 1000 * 60);

// Fetch policy.
log.info("Starting update_policy.");

// Init policy from old data.
update_policy(true);

// Update policy from server.
setTimeout(function(){
	update_policy(false);
}, 1000 * 5);

setInterval(function(){
	update_policy(false);
}, 1000 * 60);
