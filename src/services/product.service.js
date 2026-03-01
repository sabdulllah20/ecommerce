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
  image_url,
) => {
  return await pool.query(
    `
       insert into product(category_id,product_name,price,stock,user_id,image_url)
       values($1,$2,$3,$4,$5,$6)
        `,
    [category_id, product_name, price, stock, user_id, image_url],
  );
};
