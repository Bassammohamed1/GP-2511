using GP_API.Data;
using GP_API.Models;
using GP_API.Services.Interfaces;

namespace GP_API.Services
{
    public class ChildsService : IChildsService
    {
        private readonly AppDbContext _context;
        public ChildsService(AppDbContext context)
        {
            _context = context;
        }
        public IEnumerable<Child> GetAllChildren()
        {
            return _context.Children.ToList();
        }
        public Child GetChildById(int id)
        {
            var child = _context.Children.Find(id);
            return child;
        }
        public List<Child> GetChildrenByParentId(string id)
        {
            var children = _context.Children.Where(x => x.ParentId == id).ToList();
            return children;
        }
        public void AddChild(Child child)
        {
            _context.Children.Add(child);
            _context.SaveChanges();
        }

        public void UpdateChild(Child child)
        {
            _context.Children.Update(child);
            _context.SaveChanges();
        }

        public void DeleteChild(Child child)
        {
            _context.Children.Remove(child);
            _context.SaveChanges();
        }

        public void SaveChanges()
        {
            _context.SaveChanges();
        }
    }
}
