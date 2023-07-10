"""

"""

from abc import ABC, abstractmethod
import json
import sqlite3

import structlog

from server.data import utils

logger = structlog.get_logger()


class BaseDataclass(ABC):
    """This abstract class serves as the basis for every data classes."""

    def __init__(self, **kwargs):
        """Helps to construct new data objects.

        :param kwargs: The dynamic attributes to add to the class.
        """

        for key, value in kwargs.items():
            self.__dict__[key] = value

    @abstractmethod
    def save_to_db(self, db_connection: sqlite3.Connection):
        """Saves some data to the database by creating a new entry.

        :param db_connection: The connection to the database.
        :return: The object itself.
        """

        pass

    @abstractmethod
    def remove_from_db(self, db_connection: sqlite3.Connection):
        """Removes some data already present in the database.

        :param db_connection: The connection to the database.
        :return: The object itself.
        """

        pass

    def to_bson(self) -> bytes:
        """Returns the BSON representation of the current object.

        :return: The BSON representation of the current object.
        """

        return json.dumps({
            self.__class__.__name__: self.__dict__
        }).encode()

    @classmethod
    def from_json(cls, json_dump: str | bytes):
        """Loads data from JSON or BSON given in parameter.

        :param json_dump: The JSON or BSON to process.
        :return: A new instance of the class used to trigger this method.
        """

        data = json.loads(json_dump)
        try:
            data = data[cls.__name__]
        except KeyError as e:
            logger.err("No data founded in the JSON.", error=str(e))
            return
        return cls(**data)


class PopulatableDataClass(ABC):
    """This abstract class serves as the basis for every data classes that are populatable from the databse."""

    @abstractmethod
    def populate_from_db(self, db_connection: sqlite3.Connection):
        """Retrieves some data from the database.

        :param db_connection: The connection to the database.
        :return: The object itself.
        """

        pass


class UpdatableDataClass(ABC):
    """This abstract class serves as the basis for every data classes that are updatable."""

    @abstractmethod
    def update_db(self, db_connection: sqlite3.Connection):
        """Updates some data already present in the database.

        :param db_connection: The connection to the database.
        :return: The object itself.
        """

        pass


class User(BaseDataclass, PopulatableDataClass, UpdatableDataClass):
    """This class represents a single user."""

    def __init__(self,
                 username: str | None = None,
                 first_name: str | None = None,
                 last_name: str | None = None,
                 password: str | None = None,
                 user_id: int | None = None):
        """Constructs a new user.

        :param username: The username of the user.
        :param first_name: The first name of the user.
        :param last_name: The last name of the user.
        :param password: The password (or hash) of the user.
        :param user_id: The unique ID of the user.
        """

        kwargs = locals().copy().pop("self")
        super().__init__(**kwargs)

    def populate_from_db(self, db_connection: sqlite3.Connection):
        """Retrieves user's data from the database by using the user ID.

        :param db_connection: The connection to the database.
        :return: The object itself.
        """

        if self.user_id is None:
            logger.err("User's data cannot be retrieved from the database. A user ID must be set before.")
            return self

        db_cursor = db_connection.cursor()
        db_cursor.execute("SELECT * FROM users WHERE user_id = ?", (self.user_id,))
        data = db_cursor.fetchone()[0] if db_cursor.fetchone() else None
        if data is None:
            logger.info("User's data cannot be retrieved from the database. No user with this id.", user_id=self.user_id)
            return self

        cols_names = [description[0] for description in db_cursor.description]
        for col_name in cols_names:
            self.__dict__[col_name] = data[cols_names.index(col_name)]
        logger.info("User's data retrieved from the database.", user_id=self.user_id)
        return self

    def save_to_db(self, db_connection: sqlite3.Connection):
        """Saves the current user to the database by creating a new entry.

        :param db_connection: The connection to the database.
        :return: The object itself.
        """

        attributes_copy = self.__dict__.copy()
        attributes_copy.pop("user_id")
        if all(attribute is not None for attribute in list(attributes_copy.values())):
            attributes_copy["password"] = "****" if attributes_copy["password"] else None
            logger.err("It is not possible to add a new user if some values are blank. Please set them before.", **attributes_copy)
            return self
        if self.user_id is not None:
            logger.warn("A user ID is set but a new user is being created with the same data.", user_id=self.user_id)

        db_cursor = db_connection.cursor()
        db_cursor.execute("INSERT INTO users (username, first_name, last_name, password)"
                          "VALUES (?, ?, ?, ?);", (self.username, self.first_name, self.last_name, self.password))
        db_connection.commit()
        self.user_id = db_cursor.lastrowid
        logger.info("New user added to the database.", user_id=self.user_id)
        return self

    def update_db(self, db_connection: sqlite3.Connection):
        """Updates the database entry corresponding to the user ID with the attributes.

        :param db_connection: The connection to the database.
        :return: The object itself.
        """

        obfuscated_attributes = utils.obfuscate_password(self.__dict__.copy())
        if all(attribute is not None for attribute in list(obfuscated_attributes.values())):
            logger.err("All fields are mandatory to update a user in the database. Please set them before.", **obfuscated_attributes)
            return self

        db_cursor = db_connection.cursor()
        db_cursor.execute("UPDATE users SET username = ?, first_name = ?, last_name = ?, password = ?"
                          "WHERE user_id = ?;", (self.username, self.first_name, self.last_name, self.password, self.user_id))
        db_connection.commit()
        logger.info("User's data has been modified in the database.", user_id=self.user_id)
        return self

    def remove_from_db(self, db_connection: sqlite3.Connection):
        """Removes the database entry corresponding to the user ID.

        :param db_connection: The connection to the database.
        :return: The object itself.
        """

        if self.user_id is None:
            logger.err("You are trying to remove a user from the database but there is no ID. Please set it before.")
            return self

        db_cursor = db_connection.cursor()
        db_cursor.execute("DELETE FROM users WHERE user_id = ?;", (self.user_id,))
        db_connection.commit()
        logger.info("User removed from the database.", user_id=self.user_id)
        return self


class Administrator(BaseDataclass, PopulatableDataClass, UpdatableDataClass):
    """This class represents a single administrator."""

    def __init__(self,
                 username: str | None = None,
                 first_name: str | None = None,
                 last_name: str | None = None,
                 password: str | None = None,
                 administrator_id: int | None = None):
        """Constructs a new administrator.

        :param username: The username of the admin.
        :param first_name: The first name of the admin.
        :param last_name: The last name of the admin.
        :param password: The password (or hash) of the admin.
        :param administrator_id: The unique ID of the admin.
        """

        kwargs = locals().copy().pop("self")
        super().__init__(**kwargs)

    def populate_from_db(self, db_connection: sqlite3.Connection):
        """Retrieves administrator's data from the database by using the administrator ID.

        :param db_connection: The connection to the database.
        :return: The object itself.
        """

        if self.administrator_id is None:
            logger.err("Administrator's data cannot be retrieved from the database. An administrator ID must be set before.")
            return self

        db_cursor = db_connection.cursor()
        db_cursor.execute("SELECT * FROM administrators WHERE administrator_id = ?;", (self.administrator_id,))
        data = db_cursor.fetchone()[0] if db_cursor.fetchone() else None
        if data is None:
            logger.info("Administrator's data cannot be retrieved from the database. No admin with this id.", admin_id=self.admin_id)
            return self

        cols_names = [description[0] for description in db_cursor.description]
        for col_name in cols_names:
            self.__dict__[col_name] = data[cols_names.index(col_name)]
        logger.debug("Administrator's data retrieved from the database.", administrator_id=self.administrator_id)
        return self

    def save_to_db(self, db_connection: sqlite3.Connection):
        """Saves the current administrator to the database by creating a new entry.

        :param db_connection: The connection to the database.
        :return: The object itself.
        """

        attributes_copy = self.__dict__.copy()
        attributes_copy.pop("administrator_id")
        if all(attribute is not None for attribute in list(attributes_copy.values())):
            attributes_copy = utils.obfuscate_password(attributes_copy)
            logger.err("It is not possible to add a new user if some values are blank. Please set them before.", **attributes_copy)
            return self
        if self.administrator_id is not None:
            logger.warn("An administrator ID is set but a new administrator is being created with the same data.", administrator_id=self.administrator_id)

        db_cursor = db_connection.cursor()
        db_cursor.execute("INSERT INTO administrators (username, first_name, last_name, password)"
                          "VALUES (?, ?, ?, ?);", (self.username, self.first_name, self.last_name, self.password))
        db_connection.commit()
        self.administrator_id = db_cursor.lastrowid
        logger.info("New administrator added to the database.", administrator_id=self.administrator_id)
        return self

    def update_db(self, db_connection: sqlite3.Connection):
        """Updates the database entry corresponding to the administrator ID with the attributes.

        :param db_connection: The connection to the database.
        :return: The object itself.
        """

        obfuscated_attributes = utils.obfuscate_password(self.__dict__.copy())
        if all(attribute is not None for attribute in list(obfuscated_attributes.values())):
            logger.err("All fields are mandatory to update an administrator in the database. Please set them before.", **obfuscated_attributes)
            return self

        db_cursor = db_connection.cursor()
        db_cursor.execute("UPDATE administrators SET username = ?, first_name = ?, last_name = ?, password = ?"
                          "WHERE administrator_id = ?;", (self.username, self.first_name, self.last_name, self.password, self.administrator_id))
        db_connection.commit()
        logger.info("Administrator's data has been modified in the database.", administrator_id=self.administrator_id)
        return self

    def remove_from_db(self, db_connection: sqlite3.Connection):
        """Removes the database entry corresponding to the administrator ID.

        :param db_connection: The connection to the database.
        :return: The object itself.
        """

        if self.administrator_id is None:
            logger.err("You are trying to remove an administrator but there is no ID. Please set one before.")
            return self

        db_cursor = db_connection.cursor()
        db_cursor.execute("DELETE FROM administrators WHERE administrator_id = ?", (self.administrator_id,))
        db_connection.commit()
        logger.info("Administrator removed from database.", administrator_id=self.administrator_id)
        return self


class Client(BaseDataclass, PopulatableDataClass, UpdatableDataClass):
    """This class represents a single client."""

    def __init__(self,
                 name: str | None,
                 client_id: int | None = None):
        """Constructs a new client.

        :param name: The name of the client.
        :param client_id: The unique ID of the client.
        """

        kwargs = locals().copy().pop("self")
        super().__init__(**kwargs)

    def populate_from_db(self, db_connection: sqlite3.Connection):
        """Retrieves client's data from the database by using the client ID.

        :param db_connection: The connection to the database.
        :return: The object itself.
        """

        if self.client_id is None:
            logger.err("Client's data cannot be retrieved from the database. A client ID must be set before.")
            return self

        db_cursor = db_connection.cursor()
        db_cursor.execute("SELECT * FROM clients WHERE client_id = ?;", (self.client_id,))
        data = db_cursor.fetchone()[0] if db_cursor.fetchone() else None
        if data is None:
            logger.info("Client's data cannot be retrieved from the database. No client with this ID.", client_is=self.client_id)
            return self

        cols_names = [description[0] for description in db_cursor.description]
        for col_name in cols_names:
            self.__dict__[col_name] = data[cols_names.index(col_name)]
        logger.info("Client's data retrieved from the database.", client_id=self.client_id)
        return self

    def save_to_db(self, db_connection: sqlite3.Connection):
        """Saves the current client to the database by creating a new entry.

        :param db_connection: The connection to the database.
        :return: The object itself.
        """

        attributes_copy = self.__dict__.copy()
        attributes_copy.pop("client_id")
        if all(attribute is not None for attribute in list(attributes_copy.values())):
            logger.err("It is not possible to add a new client if some values are blank. Please set them before.", **attributes_copy)
            return self
        if self.client_id is not None:
            logger.warn("A client ID is set but a new client is being created with the same data.", client_id=self.client_id)

        db_cursor = db_connection.cursor()
        db_cursor.execute("INSERT INTO clients (name)"
            "VALUES (?);", (self.name,))
        db_connection.commit()
        self.client_id = db_cursor.lastrowid
        logger.info("New client added to the database.", client_id=self.client_id)
        return self

    def update_db(self, db_connection: sqlite3.Connection):
        """Updates the database entry corresponding to the client ID with the attributes.

        :param db_connection: The connection to the database.
        :return: The object itself.
        """

        attributes_copy = self.__dict__.copy()
        if all(attribute is not None for attribute in list(attributes_copy.values())):
            logger.err("All fields are mandatory to update a client in the database. Please set them before.", **attributes_copy)
            return self

        db_cursor = db_connection.cursor()
        db_cursor.execute("UPDATE clients SET name = ? WHERE client_id = ?;", (self.name, self.client_id))
        db_connection.commit()
        logger.info("Client's data has been modified in the database.", client_id=self.client_id)
        return self

    def remove_from_db(self, db_connection: sqlite3.Connection):
        """Removes the database entry corresponding to the client ID.

        :param db_connection: The connection to the database.
        :return: The object itself.
        """

        if self.client_id is None:
            logger.err("You are trying to remove a client bu there is no ID. Please set one before.")
            return self

        db_cursor = db_connection.cursor()
        db_cursor.execute("DELETE FROM clients WHERE client_id = ?;", (self.client_id,))
        db_connection.commit()
        logger.info("Client removed from the database.", client_id=self.client_id)
        return self


class Group(BaseDataclass, PopulatableDataClass, UpdatableDataClass):
    """This class represents a single group."""

    def __init__(self,
                 name: str | None,
                 group_id: int | None = None):
        """Constructs a new client.

        :param name: The name of the client.
        :param group_id: The unique ID of the client.
        """

        kwargs = locals().copy().pop("self")
        super().__init__(**kwargs)

    def populate_from_db(self, db_connection: sqlite3.Connection):
        """Retrieves group's data from the database by using the group ID.

        :param db_connection: The connection to the database.
        :return: The object itself.
        """

        if self.group_id is None:
            logger.err("Group's data cannot be retrieved from the database. A group ID must be set before.")
            return self

        db_cursor = db_connection.cursor()
        db_cursor.execute("SELECT * FROM groups WHERE group_id = ?;", (self.group_id,))
        data = db_cursor.fetchone()[0] if db_cursor.fetchone() else None
        if data is None:
            logger.info("Group's data cannot be retrieved from the database. No group with this ID.", group_id=self.group_id)
            return self

        cols_names = [description[0] for description in db_cursor.description]
        for col_name in cols_names:
            self.__dict__[col_name] = data[cols_names.index(col_name)]
        logger.info("Group's data retrieved from the database.", group_id=self.group_id)
        return self

    def save_to_db(self, db_connection: sqlite3.Connection):
        """Saves the current group to the database by creating a new entry.

        :param db_connection: The connection to the database.
        :return: The object itself.
        """

        attributes_copy = self.__dict__.copy()
        attributes_copy.pop("group_id")
        if all(attribute is not None for attribute in list(attributes_copy.values())):
            logger.err("It is not possible to add a new group if some values are blank. Please set them before.", **attributes_copy)
            return self
        if self.group_id is not None:
            logger.warn("A group ID is set but a new group is being created with the same data.", group_id=self.group_id)

        db_cursor = db_connection.cursor()
        db_cursor.execute("INSERT INTO groups (name)"
            "VALUES (?);", (self.name,))
        db_connection.commit()
        self.group_id = db_cursor.lastrowid
        logger.info("New group added to the database.", group_id=self.group_id)
        return self

    def update_db(self, db_connection: sqlite3.Connection):
        """Updates the database entry corresponding to the group ID with the attributes.

        :param db_connection: The connection to the database.
        :return: The object itself.
        """

        attributes_copy = self.__dict__.copy()
        if all(attribute is not None for attribute in list(attributes_copy.values())):
            logger.err("All fields are mandatory to update a group in the database. Please set them before.", **attributes_copy)
            return self

        db_cursor = db_connection.cursor()
        db_cursor.execute("UPDATE groups SET name = ? WHERE group_id = ?;", (self.name, self.group_id))
        db_connection.commit()
        logger.info("Group's data has been modified in the database.", group_id=self.group_id)
        return self

    def remove_from_db(self, db_connection: sqlite3.Connection):
        """Removes the database entry corresponding to the group ID.

        :param db_connection: The connection to the database.
        :return: The object itself.
        """

        if self.group_id is None:
            logger.err("You are trying to remove a group bu there is no ID. Please set one before.")
            return self

        db_cursor = db_connection.cursor()
        db_cursor.execute("DELETE FROM groups WHERE group_id = ?;", (self.group_id,))
        db_connection.commit()
        logger.info("Group removed from the database.", group_id=self.group_id)
        return self


class UserGroup(BaseDataclass):
    """This class represents a single user group couple."""

    def __init__(self, group_id: int, user_id: int):
        """Constructs a new object representing a user group couple.

        :param group_id: The ID of the group.
        :param user_id: The ID of the user.
        """

        kwargs = locals().copy().pop("self")
        super().__init__(**kwargs)

    def save_to_db(self, db_connection: sqlite3.Connection):
        """Saves the current user group couple to the database by creating a new entry.

        :param db_connection: The connection to the database.
        :return: The object itself.
        """

        if all(attribute is not None for attribute in list(self.__dict__.values())):
            logger.err("It is not possible to add a new user group couple if some values are blank. Please set them before.", **self.__dict__)

        db_cursor = db_connection.cursor()
        db_cursor.execute("INSERT INTO users_groups (group_id, user_id)"
                          "VALUES (?, ?);", (self.group_id, self.user_id))
        db_connection.commit()
        logger.info("New user group couple added to the database.", id=db_cursor.lastrowid)
        return self

    def remove_from_db(self, db_connection: sqlite3.Connection):
        """Removes the database entry corresponding to the group and user IDs.

        :param db_connection: The connection to the database.
        :return: The object itself.
        """

        if all(attribute is not None for attribute in list(self.__dict__.values())):
            logger.err("You are trying to remove a user group couple but some IDs are missing. Please set them before.")
            return self

        db_cursor = db_connection.cursor()
        db_cursor.execute("DELETE FROM users_groups WHERE group_id = ? AND user_id = ?;", (self.group_id, self.user_id))
        db_connection.commit()
        logger.info("User group couple removed from database.", group_id=self.group_id, user_id=self.user_id)
        return self


class UserGroups(BaseDataclass, PopulatableDataClass, UpdatableDataClass):
    """This class represents all the group a user belongs to."""

    def __init__(self, group_id: int, users_ids: list[int]):
        """Constructs a new object representing every user present in a group.

        :param group_id: The ID of the group.
        :param users_ids: A list containing the ID of every user.
        """

        kwargs = locals().copy().pop("self")
        super().__init__(**kwargs)

    def populate_from_db(self, db_connection: sqlite3.Connection):
        """Retrieves every user present in a group by using the group ID.

        :param db_connection: The connection to the database.
        :return: The object itself.
        """

        if self.group_id is None:
            logger.err("Users cannot be retrieved from the database. A group ID must be set before.")
            return self

        db_cursor = db_connection.cursor()
        db_cursor.execute("SELECT user_id FROM users_groups WHERE group_id = ?;", (self.group_id,))
        data = db_cursor.fetchall()
        data = [cols[0] if cols else None for cols in data]
        self.users_ids = data
        if len(self.users_ids) == 0:
            logger.info("This group is empty.", group_id=self.group_id)
            return self
        logger.info("Users present in this group have been retrieved.", group_id=self.group_id)
        return self

    def save_to_db(self, db_connection: sqlite3.Connection):
        """Saves every user group couple in the database by creating new entries.

        :param db_connection: The connection to the database.
        :return: The object itself.
        """

        self.users_ids = utils.nonify_empty_iterable(self.users_ids)
        attributes_copy = self.__dict__.copy()
        if all(attribute is not None for attribute in list(attributes_copy.values())):
            logger.err("It is not possible to add a new users to a group if some values are missing. Please set them before.", **attributes_copy)
            return self

        db_cursor = db_connection.cursor()
        for user_id in self.users_ids:
            db_cursor.execute("INSERT INTO users_groups (group_id, user_id)"
                              "VALUES (?, ?);", (self.group_id, user_id))
            db_connection.commit()
            logger.info("A new user has been added to the group.", group_id=self.group_id, user_id=user_id)
        logger.info("Every user has been added to the group.", group_id=self.group_id)
        return self

    def update_db(self, db_connection: sqlite3.Connection):
        """Updates the database entries to the ones present in this object.

        :param db_connection: The connection to the database.
        :return: The object itself.
        """

        self.remove_from_db(db_connection)
        self.save_to_db(db_connection)
        logger.info("Users present in this group have been updated.", group_id=self.group_id)
        return self

    def remove_from_db(self, db_connection: sqlite3.Connection):
        """Removes the database entries corresponding to every user group couple.

        :param db_connection: The connection to the database.
        :return: The object itself.
        """

        if self.group_id is None:
            logger.err("It is not possible to remove the users present in a group if the group ID is missing. Please set it before.")
            return self

        db_cursor = db_connection.cursor()
        db_cursor.execute("DELETE FROM users_groups WHERE group_id = ?;", (self.group_id,))
        db_connection.commit()
        logger.info("Every user group couple has been removed from the database.", group_id=self.group_id)
        return self


class GroupAccess(BaseDataclass):
    """This class represents a single group client couple."""

    def __init__(self, group_id: int, client_id: int):
        """Constructs a new object representing a client group couple.

        :param group_id: The ID of the group.
        :param client_id: The ID of the client.
        """

        kwargs = locals().copy().pop("self")
        super().__init__(**kwargs)

    def save_to_db(self, db_connection: sqlite3.Connection):
        """Saves the current client group couple to the database by creating a new entry.

        :param db_connection: The connection to the database.
        :return: The object itself.
        """

        if all(attribute is not None for attribute in list(self.__dict__.values())):
            logger.err("It is not possible to add a new user group couple if some values are blank. Please set them before.", **self.__dict__)

        db_cursor = db_connection.cursor()
        db_cursor.execute("INSERT INTO groups_accesses (group_id, client_id)"
                          "VALUES (?, ?);", (self.group_id, self.client_id))
        db_connection.commit()
        logger.info("New client group couple added to the database.", id=db_cursor.lastrowid)
        return self

    def remove_from_db(self, db_connection: sqlite3.Connection):
        """Removes the database entry corresponding to the group and client IDs.

        :param db_connection: The connection to the database.
        :return: The object itself.
        """

        if all(attribute is not None for attribute in list(self.__dict__.values())):
            logger.err("You are trying to remove a client group couple but some IDs are missing. Please set them before.")
            return self

        db_cursor = db_connection.cursor()
        db_cursor.execute("DELETE FROM groups_accesses WHERE group_id = ? AND client_id = ?;", (self.group_id, self.client_id))
        db_connection.commit()
        logger.info("Client group couple removed from database.", group_id=self.group_id, client_id=self.client_id)
        return self


class GroupAccesses(BaseDataclass):
    """This class represents all the clients a group has access to."""

    def __init__(self, group_id: int, clients_ids: list[int]):
        """Constructs a new object representing every user present in a group.

        :param group_id: The ID of the group.
        :param clients_ids: A list containing the ID of every client.
        """

        kwargs = locals().copy().pop("self")
        super().__init__(**kwargs)

    def populate_from_db(self, db_connection: sqlite3.Connection):
        """Retrieves every client present in a group by using the group ID.

        :param db_connection: The connection to the database.
        :return: The object itself.
        """

        if self.group_id is None:
            logger.err("Clients cannot be retrieved from the database. A group ID must be set before.")
            return self

        db_cursor = db_connection.cursor()
        db_cursor.execute("SELECT client_id FROM groups_accesses WHERE group_id = ?;", (self.group_id,))
        data = db_cursor.fetchall()
        data = [cols[0] if cols else None for cols in data]
        self.clients_ids = data
        if len(self.clients_ids) == 0:
            logger.info("This group is empty.", group_id=self.group_id)
            return self
        logger.info("Clients present in this group have been retrieved.", group_id=self.group_id)
        return self

    def save_to_db(self, db_connection: sqlite3.Connection):
        """Saves every client group couple in the database by creating new entries.

        :param db_connection: The connection to the database.
        :return: The object itself.
        """

        self.clients_ids = utils.nonify_empty_iterable(self.clients_ids)
        attributes_copy = self.__dict__.copy()
        if all(attribute is not None for attribute in list(attributes_copy.values())):
            logger.err("It is not possible to add a new clients to a group if some values are missing. Please set them before.", **attributes_copy)
            return self

        db_cursor = db_connection.cursor()
        for client_id in self.clients_ids:
            db_cursor.execute("INSERT INTO groups_accesses (group_id, client_id)"
                              "VALUES (?, ?);", (self.group_id, client_id))
            db_connection.commit()
            logger.info("A new client has been added to the group.", group_id=self.group_id, client_id=client_id)
        logger.info("Every client has been added to the group.", group_id=self.group_id)
        return self

    def update_db(self, db_connection: sqlite3.Connection):
        """Updates the database entries to the ones present in this object.

        :param db_connection: The connection to the database.
        :return: The object itself.
        """

        self.remove_from_db(db_connection)
        self.save_to_db(db_connection)
        logger.info("Clients present in this group have been updated.", group_id=self.group_id)
        return self

    def remove_from_db(self, db_connection: sqlite3.Connection):
        """Removes the database entries corresponding to every client group couple.

        :param db_connection: The connection to the database.
        :return: The object itself.
        """

        if self.group_id is None:
            logger.err("It is not possible to remove the clients present in a group if the group ID is missing. Please set it before.")
            return self

        db_cursor = db_connection.cursor()
        db_cursor.execute("DELETE FROM groups_accesses WHERE group_id = ?;", (self.group_id,))
        db_connection.commit()
        logger.info("Every client group couple has been removed from the database.", group_id=self.group_id)
        return self
