// import { Resend } from "resend";
// import { config } from "dotenv";
// config();

// const api = process.env.API_RESEND_EMAIL;
// const resend = new Resend(api);
// console.log(api);

// export const sendMails = async ({ to, subject, html }) => {
//   try {
//     return await resend.emails.send({
//       from: "Acme <onboarding@resend.dev>",
//       to,
//       subject,
//       html,
//     });
//   } catch (error) {
//     console.log(error);
//   }
// };

import { Resend } from "resend";
const api = process.env.API_RESEND_EMAIL;
const api2 = process.env.API2_RESEND_EMAIL;
const resend = new Resend(api);
const resend2 = new Resend(api2);

export const sendMails = async ({ to, subject, html, next }) => {
  try {
    await resend.emails.send({
      from: "Acme <onboarding@resend.dev>",
      to,
      subject,
      html,
    });
  } catch (error) {
    next(error);
  }
};
export const sendMails2 = async ({ to, subject, html, next }) => {
  try {
    const { data, error } = await resend2.emails.send({
      from: "Acme <onboarding@resend.dev>",
      to,
      subject,
      html,
    });
    if (error) {
      console.log(error);
    } else {
      console.log(data);
    }
  } catch (error) {
    next(error);
  }
};
