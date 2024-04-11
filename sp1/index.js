const express = require("express");
const handlebars = require("express-handlebars");
const app = express();

app.engine('handlebars', handlebars.engine());
app.set('view engine', 'handlebars');
app.set('views', './views');

app.get('/', (req, res) => {
    res.render('home');
});

app.listen(3001, () => {
  console.log("Service provider 1 listening on port 3001");
});
