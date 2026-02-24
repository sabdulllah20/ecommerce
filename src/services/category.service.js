import { pool } from "../database/postgreSql.js";

export const existCategory = async (category) => {
  const existCategory = await pool.query(
    `
    select * from category 
    where category_name = $1
    `,
    [category],
  );
  return existCategory.rows[0];
};

export const createCategory = async (category) => {
  return await pool.query(
    `
    insert into category 
    (category_name)
    values($1)
    `,
    [category],
  );
};
