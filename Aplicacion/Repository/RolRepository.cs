using Dominio.Entities;
using Dominio.Interfaces;
using Persistencia.Data;

namespace Aplicacion.Repository;
public class RolRepository : GenericRepository<Rol>, IRol
{
    private readonly SicerContext _Context;
    public RolRepository(SicerContext context) : base(context)
    {
        _Context = context;
    }
}
