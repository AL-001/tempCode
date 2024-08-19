async function testMethod(){
    await sleep(2000);
    console.log("console");
}
async function sleep(ms){
    console.log('abc');
    return new Promise(resolve => {
        setTimeout(()=>{
            console.log('sleep ',ms,' ms');
            resolve(ms);
        },ms);
        console.log('what');
    })
}
 testMethod();
aba = 1;
console.log(aba)
