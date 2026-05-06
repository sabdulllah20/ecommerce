import { pool } from "../database/postgreSql.js";

export const getcategoryId = async (category_name) => {
  const categoryId = await pool.query(
    `
    select * from category 
    where category_name = $1    
    `,
    [category_name],
  );
  return categoryId.rows[0];
};

export const insertProduct = async (
  category_id,
  product_name,
  price,
  stock,
  user_id,
) => {
  const product = await pool.query(
    `
       insert into product(category_id,product_name,price,stock,user_id)
       values($1,$2,$3,$4,$5)
       returning *
        `,
    [category_id, product_name, price, stock, user_id],
  );
  return product.rows[0];
};

export const insertFileInfo = async (productId, fileUrl) => {
  return await pool.query(
    `
    insert into product_files
    (product_id,file_url) 
    values($1,$2)
    `,
    [productId, fileUrl],
  );
};

export const getingAllProduct = async () => {
  const result = await pool.query(`
 
    select p.product_id, p.product_name , p.price,p.status,f.file_url from 
    users u
    inner join product  p ON  u.user_id     = p.user_id
    inner join category c ON  c.category_id = p.category_id
    inner join product_files    f ON  f.product_id   = p.product_id 
    
    `);
  return result.rows;
};

export const getingProduct = async () => {
  const allProduct = await getingAllProduct();

  const result = allProduct.reduce((acc, value) => {
    let productId = value.product_id;
    if (!acc[productId]) {
      acc[productId] = {
        product_id: value.product_id,
        name: value.product_name,
        price: {
          amount: Number(value.price),
          currency: "pkr",
        },
        images: [],
      };
    }
    acc[productId].images.push(value.file_url);
    return acc;
  }, {});
  return result;
};

export const saveCart = async (user_id) => {
  const result = await pool.query(
    `
    insert into carts (user_id)
    values($1)
    returning *
    `,
    [user_id],
  );
  return result.rows[0];
};

export const saveCartData = async (cart_id, product_id, quantity) => {
  return await pool.query(
    `
    insert into cart_items 
    (cart_id,product_id,quantity)
    values($1,$2,$3)
    `,
    [cart_id, product_id, quantity],
  );
};

export const existCart = async (user_id) => {
  const result = await pool.query(
    `
    select * from carts where user_id =$1
    `,
    [user_id],
  );
  return result.rows[0];
};

export const getCartData = async (cart_id) => {
  const result = await pool.query(
    `
    select * from cart_items ci
    inner join  product  p on  p.product_id   = ci.product_id  
    inner join  product_files  f on  f.product_id   = p.product_id  
    where ci.cart_id = $1 
    `,
    [cart_id],
  );
  return result.rows;
};
export const modifyeData = (data) => {
  const result = Object.values(
    data.reduce((acc, value) => {
      if (!acc[value.product_id]) {
        acc[value.product_id] = {
          product_id: value.product_id,
          product_name: value.product_name,
          quantity: value.quantity,
          price: Number(value.price),
          file_url: value.file_url,
        };
      }
      // acc[value.product_id].file_url.push(value.file_url);
      return acc;
    }, {}),
  );
  return result;
};
export const existProduct = async (product_id, cart_id) => {
  const result = await pool.query(
    `
    select * from cart_items 
    where product_id = $1 AND cart_id = $2     
`,

    [product_id, cart_id],
  );
  return result.rows[0];
};

export const updateQuantityProduct = async (cart_id, product_id, change) => {
  return await pool.query(
    `
    update cart_items
    set quantity = quantity + $3
    where cart_id=$1  and product_id = $2`,
    [cart_id, product_id, change],
  );
};

export const deleteCart = async (cart_id, product_id) => {
  await pool.query(
    `
    delete from cart_items
    where cart_id = $1 and product_id = $2
    returning *
    `,
    [cart_id, product_id],
  );
};
