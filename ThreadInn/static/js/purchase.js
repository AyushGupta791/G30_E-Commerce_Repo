let small1=document.getElementById("small_p_1")
let small2=document.getElementById("small_p_2")
let small3=document.getElementById("small_p_3")
let small4=document.getElementById("small_p_4")

let big1=document.getElementById("big_p_1")
let big2=document.getElementById("big_p_2")
let big3=document.getElementById("big_p_3")
let big4=document.getElementById("big_p_4")

small1.addEventListener("click",function(){
    big1.style.opacity="1";
    big2.style.opacity="0";
    big3.style.opacity="0";
    big4.style.opacity="0";
    small1.style.filter="none"
    small2.style.filter="saturate(0)"
    small3.style.filter="saturate(0)"
    small4.style.filter="saturate(0)"
    small1.style.opacity="1";
    small2.style.opacity="0.7";
    small3.style.opacity="0.7";
    small4.style.opacity="0.7";
});
small2.addEventListener("click",function(){
    big1.style.opacity="0";
    big2.style.opacity="1";
    big3.style.opacity="0";
    big4.style.opacity="0";
    small2.style.filter="none"
    small1.style.filter="saturate(0)"
    small3.style.filter="saturate(0)"
    small4.style.filter="saturate(0)"
    small2.style.opacity="1";
    small1.style.opacity="0.7";
    small3.style.opacity="0.7";
    small4.style.opacity="0.7";
});
small3.addEventListener("click",function(){
    big1.style.opacity="0";
    big2.style.opacity="0";
    big3.style.opacity="1";
    big4.style.opacity="0";
    small3.style.filter="none"
    small2.style.filter="saturate(0)"
    small1.style.filter="saturate(0)"
    small4.style.filter="saturate(0)"
    small3.style.opacity="1";
    small2.style.opacity="0.7";
    small1.style.opacity="0.7";
    small4.style.opacity="0.7";
});
small4.addEventListener("click",function(){
    big1.style.opacity="0";
    big2.style.opacity="0";
    big3.style.opacity="0";
    big4.style.opacity="1";
    small4.style.filter="none"
    small2.style.filter="saturate(0)"
    small3.style.filter="saturate(0)"
    small1.style.filter="saturate(0)"
    small4.style.opacity="1";
    small2.style.opacity="0.7";
    small3.style.opacity="0.7";
    small1.style.opacity="0.7";
});