const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt')
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const emailValidator = require('email-validator');
const registerSchema = require('./models/register');
const productsSchema = require('./models/products');

const app = express();
app.use(express.json());
app.use(bodyParser.urlencoded({extended:true}));

mongoose.connect('mongodb://127.0.0.1:27017/register');

const authToken = (req,res, next) =>{
    let jwtToken;
    const authHeader = req.headers["authorization"];
    if(authHeader !== undefined){
        jwtToken = authHeader.split(" ")[1];
    }
    if(jwtToken === undefined){
        res.send("ACCESS DENIED");
    }else{
        jwt.verify(jwtToken,"LOGIN_WITH_EMAIL", async(err, payload) =>{
            if(err){
                res.send(err);
            }else{
                next();
            }
        });
    }
}

const passwordValidator = (password) =>{
    let value;
    let message = "";
    if(password.length < 8) { 
        message = "Password must be at least 8 characters";
        value = false;
    } else if(password.search(/[a-z]/) < 0) { 
        message = "Password must contain at least one lowercase letter";
        value = false;
    } else if(password.search(/[A-Z]/) < 0) { 
        message = "Password must contain at least one uppercase letter";
        value = false; 
    } else if(password.search(/[0-9]/) < 0) { 
        message = "Password must contain at least one number";
        value = false;
    } else { 
        message = "Success!";
        value = true
    }
    return {message:message, value:value};
}

app.post('/register', async (req, res) =>{
    const {name, email, password} = req.body;
    const validatedPassword = passwordValidator(password);
    const validatedEmail = emailValidator.validate(email);
    if(!name || !email || !password){
        res.send("Name, Email & Password are required to register");
    }else{
        if(validatedEmail){
            const dbuserData = await registerSchema.findOne({email:email});
            if(dbuserData){
                res.send("User Already Exists");
            }else{
                if(validatedPassword.value){
                    const hashedPassword = await bcrypt.hash(password,10);
                    const data = {name:name, email:email, password:hashedPassword};
                    await registerSchema.create(data);
                    res.send("User Created Succesfully");
                }else{
                    res.send(validatedPassword.message);
                }                
            } 
        }else{
            res.send("Invalid Email");
        }
    }
});

app.post('/login', async(req, res) => {
    const {email, password} = req.body;
    const validatedPassword = passwordValidator(password);
    const validatedEmail = emailValidator.validate(email);
    if (validatedEmail){
        const dbuserData = await registerSchema.findOne({email:email});
        if(dbuserData === undefined){
            res.send("Invalid User");
        }else{
            if(validatedPassword.value){
                const isPasswordValid = await bcrypt.compare(password,dbuserData.password);
                if(isPasswordValid){
                    jwt.sign({email:email},"LOGIN_WITH_EMAIL");
                    res.send("Login Sucess");
                }else{
                    res.send("Incorrect password");
                }
            }else{
                res.send(validatedPassword.message);
            }
        }
    }else{
        res.send('Invalid Email');
    }
});

app.get('/', authToken,(req, res) =>{
    res.send('Home Page');
});

app.get('/products', authToken, async(req, res) =>{
    const products = await productsSchema.find();
    res.send(products);
});

app.get('/product/:id', authToken, async(req, res) =>{
    const id = req.params.id;
    const product = await productsSchema.findById(id);
    res.send(product);
});

app.post('/add-product', authToken, async(req,res)=>{
    const {name, price} = req.body;
    const product = {name:name, price:price};
    if(!name || !price){
        res.send("Name & Price are Required")
    }else{
        const productExist = await productsSchema.findOne({name:name});
        if (!productExist){
            await productsSchema.create(product);
            res.send("Product Added Successfully");
        }else{
            res.send("Product Already Exists Kindly Add another Product");
        }
    }
});

app.put('/update-product/:id', authToken, async(req,res)=>{
    const id = req.params.id;
    const {name, price} = req.body;
    const product = {name:name, price:price};
    if(!name || !price){
        res.send("Name & Price are Required")
    }else{
        const productExist = await productsSchema.findById(id);
        if (productExist){
            await productsSchema.findByIdAndUpdate(id,product);
            res.send("Product Updated Successfully");
        }else{
            res.send("Product Doesn`t Exists Kindly Add the Product");
        }
    }
});

app.delete('/delete-product/:id', authToken, async(req,res)=>{
    const id = req.params.id;
    const productExist = await productsSchema.findById(id);
    if (productExist){
        await productsSchema.findByIdAndDelete(id);
        res.send("Product Delete Successfully");
    }else{
        res.send("Product Doesn`t Exists");
    }
});


app.listen(3000, ()=>{
    console.log('Server Running at Port:3000');
});