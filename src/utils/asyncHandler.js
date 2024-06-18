const asyncHandler = (requestHandler) => {
  return (req, res, next) => {
    Promise.resolve(requestHandler(req, res, next)).catch((err) => next(err));
  };
};

export { asyncHandler };


// through try-catch(HO)

// const asyncHandler =(fn)=>async (req,res,next)=>{
//     try{
//         await fn(req,res,next)
//     }catch(err){
//         res.send(err.code || 500).json({
//             success:false,
//             message:err.message
//         })
//     }
// }
