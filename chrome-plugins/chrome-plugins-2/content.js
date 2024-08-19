setInterval(function () {
    for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        const value = localStorage.getItem(key);
        if ("hspInfoSession" == key) {
            console.log("缓存的查询记录：", value);
        } else {
            localStorage.removeItem(key);
            console.log("删除localStorage缓存", key, value);
        }
    }
}, 5000);

async function rollbackFuc() {
    while (document.oncontextmenu == null) {
        //等待被重写
        await sleep(2000); // 休眠2秒
        console.log(document.oncontextmenu, 'document.oncontextmenu')
    }
    document.oncontextmenu = (e) => {
    };
    document.onkeydown = (e) => {
    };
    window.onresize = (e) => {
    };
    checkdebugger = () => {
    };
    console.log("右键、F12开发者工具已恢复");
}

rollbackFuc().then((r, j) => {
    window.alert("插件已加载");
});


