# ruff: noqa: INP001
from pathlib import Path

from orangutan.models.type import ClassModel
from sqlmodel import Session, SQLModel, create_engine, select


def class_factory() -> type:
    def dynamic_method(self):
        return f"Dynamic method called from {self.__class__.__name__}"

    class_name = "dyn_class"
    bases: tuple = ()
    class_dict = {"attribute": 42, "method": dynamic_method}
    return type(class_name, bases, class_dict)


if not Path("./example.db").exists():
    engine = create_engine("sqlite:///example.db")
    SQLModel.metadata.create_all(engine)

    dyn_class = class_factory()
    with Session(engine) as session:
        new_class = ClassModel(name=dyn_class.__name__, type=dyn_class)
        session.add(new_class)
        session.commit()
else:
    engine = create_engine("sqlite:///example.db")
    with Session(engine) as session:
        statement = select(ClassModel).where(ClassModel.name == "dyn_class")
        result = session.exec(statement).first()

    if result and result.type:
        instance = result.type()
        print(instance.attribute)
        print(instance.method())
