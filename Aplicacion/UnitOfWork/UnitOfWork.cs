using Aplicacion.Repository;
using Dominio.Interfaces;
using Persistencia.Data;

namespace Aplicacion.UnitOfWork;
    public class UnitOfWork : IUnitOfWork, IDisposable
    {
        private readonly SicerContext ? _Context;
        public UnitOfWork(SicerContext context){
            _Context = context;
        }



        RolRepository ? _Rol;
        UsuarioRepository ? _Usuario;



        
        public IRol Roles => _Rol ??= new RolRepository(_Context!);
        public IUsuario Usuarios => _Usuario ??= new UsuarioRepository(_Context!);




        public void Dispose(){
            _Context!.Dispose();
            GC.SuppressFinalize(this); 
        }

        public Task<int> SaveAsync(){
            return _Context!.SaveChangesAsync();
        }
    }
