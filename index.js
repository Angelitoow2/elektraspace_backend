import express from "express";
import mysql from "mysql2";
import cors from "cors";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import { autenticar } from "./authMiddleware.js";
const app = express();

app.use(cors());
dotenv.config();
app.use(express.json());


const db = mysql.createConnection({
  host: process.env.MYSQLHOST,
  user: process.env.MYSQLUSER,
  password: process.env.MYSQLPASSWORD,
  database: process.env.MYSQLDATABASE,
  port: process.env.MYSQLPORT,
  ssl: {
    rejectUnauthorized: false, 
  },
});

/*------------------------------------------CORS------------------------------------------*/
app.use(
  cors({
    origin: ["https://elektraspace.vercel.app"], // dominio del frontend en Vercel
    methods: ["GET", "POST", "PUT", "DELETE"],
    credentials: true,
  })
);
/*------------------------------------------Conexión DB------------------------------------------*/
db.connect((err) => {
  if (err) {
    console.error("❌ Error al conectar con la base de datos:", err);
  } else {
    console.log("✅ Conexión exitosa con la base de datos Railway");
  }
});

/*------------------------------------------Registro------------------------------------------*/
app.post("/registrar", (req, res) => {
  const { nombres, apellidos, genero, fechaNac, correo, contrasena } = req.body;
  const sqlPerfil = `
    INSERT INTO perfil 
    (nombres, apellidos, genero, fechaNacimiento, correo, contrasena)
    VALUES (?, ?, ?, ?, ?, ?)
  `;

  db.query(
    sqlPerfil,
    [nombres, apellidos, genero, fechaNac, correo, contrasena],
    (err, result) => {
      if (err) {
        console.log("Error al insertar en perfil:", err);
        if (err.code === "ER_DUP_ENTRY") {
          return res.status(400).send("El correo ya está registrado");
        }
        return res.status(500).send("Error al registrar perfil");
      } else {
        const idPerfil = result.insertId;
        const sqlUsuario = "INSERT INTO usuario (idPerfil) VALUES (?)";
        db.query(sqlUsuario, [idPerfil], (err2) => {
          if (err2) {
            console.log("Error al insertar en usuario:", err2);
            res.status(500).send("Error al registrar usuario");
          } else {
            res.send("✅ Usuario registrado correctamente");
          }
        });
      }
    }
  );
});

/*--------------------------------------------Login------------------------------------------*/
app.post("/login", (req, res) => {
  const { correo, contrasena } = req.body;

  const sqlPerfil = "SELECT * FROM perfil WHERE correo = ? AND contrasena = ?";
  db.query(sqlPerfil, [correo, contrasena], (err, perfilResult) => {
    if (err) {
      console.log("❌ Error al buscar perfil:", err);
      return res.status(500).json({ message: "Error interno del servidor" });
    }

    if (perfilResult.length === 0) {
      return res
        .status(401)
        .json({ message: "Correo o contraseña incorrectos" });
    }

    const perfil = perfilResult[0];
    const idPerfil = perfil.idPerfil;

    // Buscar si el perfil es administrador
    const sqlAdmin = "SELECT * FROM administrador WHERE idPerfil = ?";
    db.query(sqlAdmin, [idPerfil], (err2, adminResult) => {
      if (err2) {
        console.log("❌ Error al buscar administrador:", err2);
        return res.status(500).json({ message: "Error interno del servidor" });
      }

      // Determinar rol
      const rol = adminResult.length > 0 ? "admin" : "usuario";

      const usuario = {
        idPerfil: perfil.idPerfil,
        nombres: perfil.nombres,
        apellidos: perfil.apellidos,
        correo: perfil.correo,
        temaVisual: perfil.temaVisual,
        rol,
      };

      // Generar token JWT
      const token = jwt.sign(
        { idPerfil: perfil.idPerfil, correo: perfil.correo },
        process.env.JWT_SECRET,
        { expiresIn: "2h" }
      );

      console.log("✅ Usuario autenticado:", usuario);
      res.status(200).json({ loggedIn: true, usuario, token });
    });
  });
});

/*------------------------------------------Traer todos los módulos------------------------------------------*/
app.get("/modulos", (req, res) => {
  const sql = "SELECT * FROM modulo";
  db.query(sql, (err, result) => {
    if (err) {
      console.error("Error al obtener módulos:", err);
      return res.status(500).json({ message: "Error al obtener módulos" });
    }
    res.json(result); // devuelve los módulos como JSON
  });
});
/*------------------------------------------Activar DB------------------------------------------*/
app.listen(3001, () => {
  console.log("Server is running on port 3001");
});
/*------------------------------------------Temas------------------------------------------*/
app.post("/tema", autenticar, (req, res) => {
  const { temaVisual } = req.body;
  const idPerfil = req.user.idPerfil;
  const sqlPerfil = `
    UPDATE perfil 
    SET temaVisual = ?
    WHERE idPerfil = ?
  `;
  db.query(sqlPerfil, [temaVisual, idPerfil], (err, result) => {
    if (err) {
      console.log("Error al actualizar en perfil:", err);
      return res
        .status(500)
        .json({ error: "Error al actualizar el tema del perfil" });
    } else {
      res.json({ success: true, message: "Tema actualizado correctamente" });
    }
  });
});
/*------------------------------------------Actualizar contraseña------------------------------------------*/
app.post("/contrasena", autenticar, (req, res) => {
  const { contrasenaActual, nuevaContrasena } = req.body;
  const idPerfil = req.user.idPerfil;

  // Verificar la contraseña actual
  const sqlVerificar = "SELECT contrasena FROM perfil WHERE idPerfil = ?";
  db.query(sqlVerificar, [idPerfil], (err, result) => {
    if (err) {
      console.error("Error al verificar contraseña:", err);
      return res
        .status(500)
        .json({ message: "Error al verificar la contraseña" });
    }

    if (result.length === 0) {
      return res.status(404).json({ message: "Usuario no encontrado" });
    }

    const contrasenaGuardada = result[0].contrasena;
    if (contrasenaGuardada !== contrasenaActual) {
      return res
        .status(401)
        .json({ message: "La contraseña actual es incorrecta" });
    }

    // Actualizar si todo está bien
    const sqlActualizar = "UPDATE perfil SET contrasena = ? WHERE idPerfil = ?";
    db.query(sqlActualizar, [nuevaContrasena, idPerfil], (err2) => {
      if (err2) {
        console.error("Error al actualizar contraseña:", err2);
        return res
          .status(500)
          .json({ message: "Error al actualizar la contraseña" });
      }

      res.json({
        success: true,
        message: "Contraseña actualizada correctamente",
      });
    });
  });
});

/*------------------------------------------ Registrar Historial de Acceso ------------------------------------------*/
app.post("/historial", autenticar, (req, res) => {
  const idPerfil = req.user.idPerfil;
  const { idModulo } = req.body;

  // Verificar si ya existe un historial abierto (sin salida) para este usuario y módulo
  const checkSql = `
    SELECT idHistorial FROM historialAcceso
    WHERE idPerfilUsuario = ? AND idModulo = ? AND fechaSalidaModulo IS NULL
    LIMIT 1
  `;

  db.query(checkSql, [idPerfil, idModulo], (err, rows) => {
    if (err) {
      console.error("❌ Error al verificar historial:", err);
      return res.status(500).json({ message: "Error al verificar historial" });
    }

    if (rows.length > 0) {
      // Ya hay una sesión activa devuelve el mismo idHistorial
      return res.json({
        message: "⚠️ Sesión ya abierta para este módulo",
        idHistorial: rows[0].idHistorial,
      });
    }

    // No hay sesión abierta registrar nuevo ingreso
    const insertSql = `
      INSERT INTO historialAcceso (idPerfilUsuario, idModulo, fechaIngresoModulo)
      VALUES (?, ?, NOW())
    `;

    db.query(insertSql, [idPerfil, idModulo], (err, result) => {
      if (err) {
        console.error("❌ Error al registrar ingreso:", err);
        return res.status(500).json({ message: "Error al registrar ingreso" });
      }

      res.json({
        message: "✅ Ingreso al módulo registrado correctamente",
        idHistorial: result.insertId,
      });
    });
  });
});

/*------------------------------------------ Registrar Salida ------------------------------------------*/
app.put("/historial/salida/:idHistorial", autenticar, (req, res) => {
  const { idHistorial } = req.params;

  const sql = `
    UPDATE historialAcceso
    SET fechaSalidaModulo = NOW(),
        tiempoUso = ROUND(TIMESTAMPDIFF(SECOND, fechaIngresoModulo, NOW()) / 60, 2)
    WHERE idHistorial = ? AND fechaSalidaModulo IS NULL
  `;

  db.query(sql, [idHistorial], (err, result) => {
    if (err) {
      console.error("❌ Error al registrar salida:", err);
      return res.status(500).json({ message: "Error al registrar salida" });
    }

    if (result.affectedRows === 0) {
      return res
        .status(404)
        .json({ message: "No se encontró historial activo para actualizar" });
    }

    res.json({
      message: "✅ Salida registrada correctamente y tiempo de uso calculado",
    });
  });
});

/*------------------------------------------ Buscar Último Historial ------------------------------------------*/
app.get("/historial/:idModulo", autenticar, (req, res) => {
  const idPerfil = req.user.idPerfil;
  const idModulo = req.params.idModulo;

  const sql = `
    SELECT idHistorial, fechaIngresoModulo, fechaSalidaModulo, tiempoUso
    FROM historialAcceso
    WHERE idPerfilUsuario = ? AND idModulo = ?
    ORDER BY fechaIngresoModulo DESC
    LIMIT 1
  `;

  db.query(sql, [idPerfil, idModulo], (err, result) => {
    if (err) {
      console.error("❌ Error al obtener historial:", err);
      return res.status(500).json({ message: "Error al obtener historial" });
    }

    if (result.length === 0) {
      return res
        .status(404)
        .json({ message: "Sin registros para este módulo" });
    }

    res.json(result[0]);
  });
});
/*------------------------------------------Ruta Raíz------------------------------------------*/
app.get("/", (req, res) => {
  res.send("Backend de ElektraSpace funcionando correctamente");
});


/*------------------------------------------Activar DB------------------------------------------*/
app.listen(process.env.PORT || 3001, () => {
  console.log("Server is running on port " + (process.env.PORT || 3001));
});