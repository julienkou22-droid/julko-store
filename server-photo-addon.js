// A intégrer dans server.js consolidé JULKO STORE.
// Requiert: const multer = require('multer');
// Requiert aussi path, fs et crypto déjà utilisés par le serveur consolidé.
const UPLOAD_DIR = process.env.UPLOAD_DIR || '/data/uploads';
fs.mkdirSync(UPLOAD_DIR,{recursive:true});
app.use('/uploads',express.static(UPLOAD_DIR));
const imageStorage=multer.diskStorage({
  destination:(_req,_file,cb)=>cb(null,UPLOAD_DIR),
  filename:(_req,file,cb)=>cb(null,Date.now()+'-'+crypto.randomBytes(8).toString('hex')+(path.extname(file.originalname).toLowerCase()||'.jpg'))
});
const uploadImage=multer({
  storage:imageStorage,
  limits:{fileSize:5*1024*1024},
  fileFilter:(_req,file,cb)=>{
    const ok=['image/jpeg','image/png','image/webp'].includes(file.mimetype);
    cb(ok?null:new Error('Format image non autorisé'),ok);
  }
});
app.post('/api/admin/upload-image',admin,uploadImage.single('image'),(req,res)=>{
  if(!req.file)return res.status(400).json({error:'Image requise'});
  res.status(201).json({url:'/uploads/'+req.file.filename});
});
