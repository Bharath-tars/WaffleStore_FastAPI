from fastapi import FastAPI, HTTPException, Depends
from firebase_admin import credentials, db, initialize_app
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import uuid
import os
import json
import firebase_admin

app = FastAPI()

# # Firebase Admin Setup
# cred = credentials.Certificate("ecommerce-fedbd-firebase-adminsdk-87x48-aad7642618.json")
# initialize_app(cred, {
#     "databaseURL": "https://ecommerce-fedbd-default-rtdb.firebaseio.com/"
# })

if not firebase_admin._apps:
    CredentialCertificate = os.environ.get('CREDENTIALCERTIFICATE')
    firebase_credentials_dict = json.loads(CredentialCertificate)
    cred = credentials.Certificate(firebase_credentials_dict)
    firebase_admin.initialize_app(cred, {
        'databaseURL': "https://ecommerce-fedbd-default-rtdb.firebaseio.com/"
    })


# OAuth2 Setup for Login and Authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="admin/login")

# Models
class AdminOperation(BaseModel):
    operation_id: str
    admin_name: str
    operation_type: str
    details: str
    timestamp: str

class Admin(BaseModel):
    name: str
    username: str
    password: str
    history_operations: List[AdminOperation] = []

class InventoryItem(BaseModel):
    product_name: str
    product_price: float
    quantity: int
    category: str
    tags: List[str]

class SaleProduct(BaseModel):
    product_name: str
    quantity: int

class Sale(BaseModel):
    sale_id: str
    products: List[SaleProduct]
    total_amount: float
    timestamp: str

# Helper Functions
def log_admin_operation(admin_username: str, operation_type: str, details: str):
    """Log an operation performed by an admin."""
    ref = db.reference("admins")
    admin = ref.child(admin_username).get()

    if not admin:
        raise HTTPException(status_code=404, detail="Admin not found")

    admin_name = admin["name"]
    operation_id = str(uuid.uuid4())
    timestamp = datetime.now().isoformat()
    operation = {
        "operation_id": operation_id,
        "admin_name": admin_name,
        "operation_type": operation_type,
        "details": details,
        "timestamp": timestamp
    }

    history = admin.get("history_operations", [])
    history.append(operation)
    ref.child(admin_username).update({"history_operations": history})

    log_ref = db.reference("logs")
    log_ref.push(operation)
    return operation_id


@app.post("/admin/signup", summary="Sign Up a new admin", description="Create a new admin profile.")
async def admin_signup(admin: Admin):
    try:
        ref = db.reference("admins")
        if ref.child(admin.username).get():
            raise HTTPException(status_code=400, detail="Username already exists")

        ref.child(admin.username).set(admin.dict())
        return {"message": "Admin signed up successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to signup: {str(e)}")



@app.post("/admin/login", summary="Login an admin", description="Login with a username and password.")
async def admin_login(form_data: OAuth2PasswordRequestForm = Depends()):
    try:
        ref = db.reference("admins")
        admin = ref.child(form_data.username).get()

        if not admin or admin["password"] != form_data.password:
            raise HTTPException(status_code=400, detail="Invalid username or password")

        return {"access_token": admin["username"], "token_type": "bearer"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to login: {str(e)}")



# @app.post("/admin/inventory_cu", summary="Add or update inventory items", description="Add a new product or update an existing product's quantity.")
# async def add_or_update_inventory(item: InventoryItem, token: str = Depends(oauth2_scheme)):
#     try:
#         admin_ref = db.reference("admins")
#         admin = admin_ref.child(token).get()
#         if not admin:
#             raise HTTPException(status_code=403, detail="Unauthorized access")

#         ref = db.reference("inventory")
#         inventory = ref.get()

#         # Check if the product already exists
#         for key, value in inventory.items() if inventory else []:
#             if value["product_name"] == item.product_name:
#                 updated_quantity = value["quantity"] + item.quantity
#                 ref.child(key).update({"quantity": updated_quantity})
#                 operation_id = log_admin_operation(token, "Update Inventory", f"Updated {item.product_name} quantity to {updated_quantity}")
#                 return {"message": "Inventory updated successfully", "operation_id": operation_id}

#         # Add new product
#         ref.push(item.dict())
#         operation_id = log_admin_operation(token, "Add Inventory", f"Added new product {item.product_name} with quantity {item.quantity}")
#         return {"message": "Inventory item added successfully", "operation_id": operation_id}
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=f"Failed to add or update inventory: {str(e)}")


@app.post("/admin/inventory/add",summary="Add a new product to the inventory",description="Add a product with details like name, price, quantity, category, and tags.")
async def add_product(item: InventoryItem, token: str = Depends(oauth2_scheme)):
    try:
        # Verify admin token
        admin_ref = db.reference("admins")
        admin = admin_ref.child(token).get()
        if not admin:
            raise HTTPException(status_code=403, detail="Unauthorized access")

        # References to database nodes
        inventory_ref = db.reference("inventory")
        categories_ref = db.reference("categories")
        tags_ref = db.reference("tags")

        # Check if the product already exists
        existing_product = inventory_ref.child(item.product_name).get()
        if existing_product:
            raise HTTPException(
                status_code=400, detail=f"Product '{item.product_name}' already exists in the inventory."
            )

        # Add product to inventory
        product_data = {
            "price": item.product_price,
            "quantity": item.quantity,
            "category": item.category,
            "tags": item.tags,
        }
        inventory_ref.child(item.product_name).set(product_data)

        # Add category if not already present
        category_products = categories_ref.child(item.category).get()
        if not category_products:
            categories_ref.child(item.category).set([])
        categories_ref.child(item.category).push(item.product_name)

        # Add tags if not already present
        for tag in item.tags:
            tag_products = tags_ref.child(tag).get()
            if not tag_products:
                tags_ref.child(tag).set([])
            tags_ref.child(tag).push(item.product_name)

        # Log admin operation
        operation_id = log_admin_operation(
            token,
            "Add Product",
            f"Added product '{item.product_name}' with price {item.product_price}, quantity {item.quantity}, category '{item.category}', and tags {item.tags}.",
        )

        return {"message": f"Product '{item.product_name}' added successfully.", "operation_id": operation_id}

    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to add product: {str(e)}"
        )




@app.delete("/admin/inventory_delete", summary="Delete an inventory item", description="Delete a product from the inventory.")
async def delete_inventory_item(product_name: str, token: str = Depends(oauth2_scheme)):
    try:
        admin_ref = db.reference("admins")
        admin = admin_ref.child(token).get()
        if not admin:
            raise HTTPException(status_code=403, detail="Unauthorized access")

        ref = db.reference("inventory")
        inventory = ref.get()

        for key, value in inventory.items() if inventory else []:
            if key == product_name:
                ref.child(key).delete()
                operation_id = log_admin_operation(token, "Delete Inventory", f"Deleted product {product_name}")
                return {"message": "Inventory item deleted successfully", "operation_id": operation_id}

        raise HTTPException(status_code=404, detail=f"Product {product_name} not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete inventory item: {str(e)}")




@app.get("/admin/inventory_list", summary="List all inventory items", description="Retrieve all inventory items.")
async def list_inventory(token: str = Depends(oauth2_scheme)):
    try:
        ref = db.reference("inventory")
        inventory = ref.get()
        return {"inventory": [key for key,value in inventory.items()] if inventory else []}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch inventory: {str(e)}")


@app.get("/admin/inventory/categories", summary="Retrieve all categories", description="Get a list of all categories.")
async def get_all_categories(token: str = Depends(oauth2_scheme)):
    try:
        admin_ref = db.reference("admins")
        admin = admin_ref.child(token).get()
        if not admin:
            raise HTTPException(status_code=403, detail="Unauthorized access")
        categories_ref = db.reference("categories")
        categories = categories_ref.get()
        if not categories:
            return {"categories": [], "message": "No categories found."}

        return {"categories": list(categories.keys())}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve categories: {str(e)}")



@app.get("/admin/inventory/tags", summary="Retrieve all tags", description="Get a list of all tags in the inventory.")
async def get_all_tags(token: str = Depends(oauth2_scheme)):
    try:
        admin_ref = db.reference("admins")
        admin = admin_ref.child(token).get()
        if not admin:
            raise HTTPException(status_code=403, detail="Unauthorized access")
        tags_ref = db.reference("tags")
        all_tags = tags_ref.get()

        if not all_tags:
            return {"tags": [], "message": "No tags found."}
        return {"tags": list(all_tags.keys())}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve tags: {str(e)}")


# @app.get("/admin/inventory/category/{category_name}", summary="Retrieve items by category", description="Get all items belonging to a specific category.")
# async def get_items_by_category(category_name: str, token: str = Depends(oauth2_scheme)):
#     try:
#         admin_ref = db.reference("admins")
#         admin = admin_ref.child(token).get()
#         if not admin:
#             raise HTTPException(status_code=403, detail="Unauthorized access")
#         categories_ref = db.reference("categories")
#         category_items = categories_ref.child(category_name).get()
#         if not category_items:
#             raise HTTPException(status_code=404, detail=f"No items found under the category '{category_name}'.")

#         return {"category": category_name, "items": list(category_items.keys())}
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=f"Failed to retrieve items by category: {str(e)}")


#item by category
@app.get("/admin/inventory/category/{category_name}", summary="Retrieve items by category name", description="Get all items belonging to a specific category.")
async def get_items_by_category(category_name: str, token: str = Depends(oauth2_scheme)):
    try:
        admin_ref = db.reference("admins")
        admin = admin_ref.child(token).get()
        if not admin:
            raise HTTPException(status_code=403, detail="Unauthorized access")
        
        categories_ref = db.reference("categories")
        category_items = categories_ref.child(category_name).get()
        if not category_items:
            raise HTTPException(status_code=404, detail=f"No items found under the category '{category_name}'.")

        # Retrieve product names based on the category
        items = [product for product in category_items.values()]
        
        return {"category": category_name, "items": items}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve items by category: {str(e)}")


#product details
@app.get("/admin/inventory/product/{product_name}", summary="Retrieve product details by product name", description="Get details of a specific product.")
async def get_product_details(product_name: str, token: str = Depends(oauth2_scheme)):
    try:
        admin_ref = db.reference("admins")
        admin = admin_ref.child(token).get()
        if not admin:
            raise HTTPException(status_code=403, detail="Unauthorized access")
        products_ref = db.reference("inventory")
        product_details = None
        for product_name_db, product_details_db in products_ref.get().items():
            if product_name_db == product_name:
                product_details = product_details_db
                break
        if not product_details:
            raise HTTPException(status_code=404, detail=f"Product '{product_name}' not found.")
        return {"product_name": product_name, "details": product_details}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve product details: {str(e)}")



#item by tag
@app.get("/admin/inventory/tag/{tag_name}", summary="Retrieve items by tag", description="Get all items associated with a specific tag.")
async def get_items_by_tag(tag_name: str, token: str = Depends(oauth2_scheme)):
    try:
        admin_ref = db.reference("admins")
        admin = admin_ref.child(token).get()
        if not admin:
            raise HTTPException(status_code=403, detail="Unauthorized access")
        tags_ref = db.reference("tags")
        tag_items = tags_ref.child(tag_name).get()
        if not tag_items:
            raise HTTPException(status_code=404, detail=f"No items found under the tag '{tag_name}'.")
        return {"tag": tag_name, "items": list(tag_items.values())}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve items by tag: {str(e)}")


#search products by keyword
@app.get("/admin/inventory/search", summary="Search products by keyword", description="Search products by keyword (starts with).")
async def search_products(keyword: str, token: str = Depends(oauth2_scheme)):
    try:
        admin_ref = db.reference("admins")
        admin = admin_ref.child(token).get()
        if not admin:
            raise HTTPException(status_code=403, detail="Unauthorized access")

        products_ref = db.reference("inventory")
        matching_products = []

        for product_name_db, product_data in products_ref.get().items():
            if product_name_db.lower().startswith(keyword.lower()):
                matching_products.append(product_name_db)
        
        if not matching_products:
            raise HTTPException(status_code=404, detail=f"No products found starting with '{keyword}'.")
        return {"keyword": keyword, "products": matching_products}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to search products: {str(e)}")




#create collection and add product to it
@app.post("/admin/inventory/collection", summary="Create collection and add product to a collection", description="Add a product to a collection. Create a new collection if it does not exist.")
async def add_product_to_collection(
    collection_name: str, 
    product_name: str, 
    token: str = Depends(oauth2_scheme)
):
    try:
        admin_ref = db.reference("admins")
        admin = admin_ref.child(token).get()
        if not admin:
            raise HTTPException(status_code=403, detail="Unauthorized access")

        collections_ref = db.reference("collections")
        collection = collections_ref.child(collection_name).get()

        inventory_ref = db.reference("inventory")
        product = inventory_ref.child(product_name).get()

        if not product:
            raise HTTPException(status_code=404, detail=f"Product '{product_name}' not found in inventory.")
        if collection and product_name in collection:
                    return {"message": f"Product '{product_name}' already exists in collection '{collection_name}'."}
        if not collection:
            collections_ref.child(collection_name).child(product_name).set(product)
        else:
            collections_ref.child(collection_name).child(product_name).set(product)
        operation_id = log_admin_operation(
            token,
            "Created Collection and Added Product",
            f"Added product of name '{product}' to collection of name '{collection_name}'.",
        )
        return {"message": f"Product '{product_name}' successfully added to collection '{collection_name}'.", operation_id: operation_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to add product to collection: {str(e)}")




#remove a collection
@app.delete("/admin/inventory/remove_collection", summary="Remove a collection", description="Delete an entire collection and its associated products.")
async def remove_collection(collection_name: str, token: str = Depends(oauth2_scheme)):
    try:
        admin_ref = db.reference("admins")
        admin = admin_ref.child(token).get()
        if not admin:
            raise HTTPException(status_code=403, detail="Unauthorized access")
        collections_ref = db.reference("collections")
        collection = collections_ref.child(collection_name).get()
        if not collection:
            raise HTTPException(status_code=404, detail=f"Collection '{collection_name}' does not exist.")
        collections_ref.child(collection_name).delete()
        operation_id = log_admin_operation(
            token,
            "Removed Collection",
            f"Removed collection of name '{collection_name}'.",
        )
        return {"message": f"Collection '{collection_name}' removed successfully.", "operation_id": operation_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to remove collection: {str(e)}")




#remove product from collection
@app.delete("/admin/inventory/collection/remove_product", summary="Remove a product from a collection", description="Remove a product from an existing collection.")
async def remove_product_from_collection(collection_name: str, product_name: str, token: str = Depends(oauth2_scheme)):
    try:
        admin_ref = db.reference("admins")
        admin = admin_ref.child(token).get()
        if not admin:
            raise HTTPException(status_code=403, detail="Unauthorized access")
        collections_ref = db.reference("collections")
        collection = collections_ref.child(collection_name).get()
        if not collection:
            raise HTTPException(status_code=404, detail=f"Collection '{collection_name}' does not exist.")
        product_details = collection.get(product_name)
        if not product_details:
            raise HTTPException(status_code=404, detail=f"Product '{product_name}' does not exist in the collection '{collection_name}'.")
        collections_ref.child(collection_name).child(product_name).delete()
        operation_id = log_admin_operation(
            token,
            "Removed Product from Collection",
            f"Removed product of name '{product_name}' from collection of name '{collection_name}'.",
        )
        return {"message": f"Product '{product_name}' removed from collection '{collection_name}' successfully.", "operation_id": operation_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to remove product from collection: {str(e)}")



#get all collection names
@app.get("/admin/inventory/list_collection", summary="Retrieve all the existing collections", description="Get all the collection names that are existing.")
async def get_items_by_collection(token: str = Depends(oauth2_scheme)):
    try:
        admin_ref = db.reference("admins")
        admin = admin_ref.child(token).get()
        if not admin:
            raise HTTPException(status_code=403, detail="Unauthorized access")
        collections_ref = db.reference("collections")
        collection_items = collections_ref.get()
        if not collection_items:
            raise HTTPException(status_code=404, detail=f"No Collections found.")
        return {"Collection_names": list(collection_items.keys())}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch collection: {str(e)}")



#get items by collection
@app.get("/admin/inventory/collection/{collection_name}", summary="Retrieve items by collection", description="Get all items belonging to a specific collection.")
async def get_items_by_collection(collection_name: str, token: str = Depends(oauth2_scheme)):
    try:
        admin_ref = db.reference("admins")
        admin = admin_ref.child(token).get()
        if not admin:
            raise HTTPException(status_code=403, detail="Unauthorized access")
        collections_ref = db.reference("collections")
        collection_items = collections_ref.child(collection_name).get()
        if not collection_items:
            raise HTTPException(status_code=404, detail=f"No items found under the collection '{collection_name}'.")
        items = [{product:details} for product,details in collection_items.items()]
        return {"collection": collection_name, "items": items}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve items by collection: {str(e)}")



#admin logs
@app.get("/admin/logs", summary="Get admin logs", description="Retrieve logs of all admin operations.")
async def get_admin_logs(token: str = Depends(oauth2_scheme)):
    try:
        ref = db.reference("logs")
        logs = ref.get()
        return {"logs": [log for log in logs.values()] if logs else []}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch logs: {str(e)}")


# Get admin info
@app.get("/admin/list", summary="List all admins and their operation IDs", description="Retrieve all admins and their operation IDs.")
async def list_admins(token: str = Depends(oauth2_scheme)):
    try:
        admin_ref = db.reference("admins")
        admins = admin_ref.get()
        if not admins:
            return {"admins": []}
        admin_list = []
        for key, value in admins.items():
            admin_operations = value.get("history_operations", [])
            admin_list.append({
                "admin_name": value["name"],
                "username": value["username"],
                "operation_ids": [op["operation_id"] for op in admin_operations]
            })
        return {"admins": admin_list}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch admin list: {str(e)}")
    


@app.get("/admin/operation/{operation_id}", summary="Retrieve operation by ID", description="Retrieve a specific admin operation by its ID.")
async def get_operation_by_id(operation_id: str, token: str = Depends(oauth2_scheme)):
    try:
        admin_ref = db.reference("admins")
        admins = admin_ref.get()
        if not admins:
            raise HTTPException(status_code=404, detail="No admins found")
        for admin in admins.values():
            history_operations = admin.get("history_operations", [])
            for operation in history_operations:
                if operation["operation_id"] == operation_id:
                    return {
                        "username": admin["username"],
                        "operation": operation
                    }

        raise HTTPException(status_code=404, detail=f"Operation with ID {operation_id} not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve operation: {str(e)}")
    


# @app.get("/admin/operations", summary="Retrieve all operations", description="Retrieve all admin operations.")
# async def get_all_operations(token: str = Depends(oauth2_scheme)):
#     try:
#         admin_ref = db.reference("admins")
#         admins = admin_ref.get()

#         if not admins:
#             raise HTTPException(status_code=404, detail="No admins found")

#         all_operations = []
#         for admin in admins.values():
#             history_operations = admin.get("history_operations", [])
#             for operation in history_operations:
#                 all_operations.append({
#                     "username": admin["username"],
#                     "operation": operation
#                 })

#         return {"operations": all_operations}
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=f"Failed to retrieve operations: {str(e)}")
    

@app.get("/admin/operations/{username}", summary="Retrieve operations by username", description="Retrieve all operations performed by a specific admin.")
async def get_operations_by_username(username: str, token: str = Depends(oauth2_scheme)):
    try:
        admin_ref = db.reference("admins")
        admin = admin_ref.child(username).get()

        if not admin:
            raise HTTPException(status_code=404, detail="Admin not found")

        history_operations = admin.get("history_operations", [])
        return {"operations": history_operations}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve operations: {str(e)}")


# update quantity of a product with number and + or - sign
@app.put("/admin/inventory_update", summary="Update inventory quantity", description="Update the quantity of a product in the inventory.")
async def update_inventory_quantity(product_name: str, quantity: int, sign: str, token: str = Depends(oauth2_scheme)):
    try:
        admin_ref = db.reference("admins")
        admin = admin_ref.child(token).get()
        if not admin:
            raise HTTPException(status_code=403, detail="Unauthorized access")

        ref = db.reference("inventory")
        inventory = ref.get()

        for key, value in inventory.items() if inventory else []:
            if key == product_name:
                if sign == "+":
                    updated_quantity = value["quantity"] + quantity
                elif sign == "-":
                    updated_quantity = value["quantity"] - quantity
                ref.child(key).update({"quantity": updated_quantity})
                operation_id = log_admin_operation(token, "Update Inventory", f"Updated {product_name} quantity to {updated_quantity}")
                return {"message": "Inventory updated successfully", "operation_id": operation_id}

        raise HTTPException(status_code=404, detail=f"Product {product_name} not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update inventory quantity: {str(e)}")
    


# get the stats of the inventory
@app.get("/admin/inventory/stats", summary="Get overall inventory stats", description="Retrieve statistics like total items, total quantity, and total cost in the inventory.")
async def get_inventory_stats(token: str = Depends(oauth2_scheme)):
    try:
        admin_ref = db.reference("admins")
        admin = admin_ref.child(token).get()
        if not admin:
            raise HTTPException(status_code=403, detail="Unauthorized access")

        inventory_ref = db.reference("inventory")
        inventory = inventory_ref.get()

        if not inventory:
            return {
                "total_items": 0,
                "total_quantity": 0,
                "total_cost": 0.0,
                "message": "No inventory items found."
            }

        total_items = len(inventory)
        total_quantity = 0
        total_cost = 0.0

        for product_code, product_data in inventory.items():
            quantity = product_data.get("quantity", 0)
            cost = product_data.get("price", 0.0)
            total_quantity += quantity
            total_cost += quantity * cost

        return {
            "total_items_type": total_items,
            "total_items_quantity": total_quantity,
            "total_cost": total_cost
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve inventory stats: {str(e)}")
    


@app.post("/admin/logout", summary="Logout admin", description="Invalidate the admin's token to log out.")
async def admin_logout(token: str = Depends(oauth2_scheme)):
    try:
        blacklist_ref = db.reference("blacklisted_tokens")
        blacklisted_tokens = blacklist_ref.get() or {}
        if token in blacklisted_tokens.values():
            raise HTTPException(status_code=403, detail="Token is already invalidated")

        admin_ref = db.reference("admins")
        admins = admin_ref.get()

        if not admins:
            raise HTTPException(status_code=404, detail="No admins found")

        for admin_key, admin in admins.items():
            if admin["username"] == token:
                blacklist_ref.push(token)
                log_admin_operation(admin["username"], "Logout", f"Admin {admin['name']} logged out")
                return {"message": f"Admin {admin['name']} logged out successfully"}

        raise HTTPException(status_code=403, detail="Invalid token or admin not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to log out: {str(e)}")



# @app.put("/admin/inventory/rename", summary="Rename an inventory product name", description="Rename an existing product name in the inventory.")
# async def rename_product_name(old_product_name: str, new_product_name: str, token: str = Depends(oauth2_scheme)):
#     try:
#         admin_ref = db.reference("admins")
#         admin = admin_ref.child(token).get()
#         if not admin:
#             raise HTTPException(status_code=403, detail="Unauthorized access")
#         # Reference to the inventory node
#         inventory_ref = db.reference("inventory")
#         inventory = inventory_ref.get()

#         if not inventory:
#             raise HTTPException(status_code=404, detail="Inventory is empty.")

#         # Flag to check if the product was renamed
#         renamed = False

#         for prod_name, prod_details in inventory.items():
#             if prod_name == old_product_name:
#                 inventory_ref.child().update({"product_name": new_product_name})
#                 renamed = True

#         if not renamed:
#             raise HTTPException(status_code=404, detail=f"Product name '{old_product_name}' not found.")

#         operation_id = log_admin_operation(
#             token,
#             "Rename Product Name",
#             f"Renamed product name from '{old_product_name}' to '{new_product_name}'."
#         )
#         return {"message": f"Product name '{old_product_name}' renamed to '{new_product_name}' successfully.", "operation_id": operation_id}
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=f"Failed to rename product name: {str(e)}")


#rename product name
@app.put("/admin/inventory/rename", summary="Rename an inventory product name", description="Rename an existing product name in the inventory.")
async def rename_product_name(old_product_name: str, new_product_name: str, token: str = Depends(oauth2_scheme)):
    try:
        admin_ref = db.reference("admins")
        admin = admin_ref.child(token).get()
        if not admin:
            raise HTTPException(status_code=403, detail="Unauthorized access")
        
        # Reference to the inventory node
        inventory_ref = db.reference("inventory")
        product_ref = inventory_ref.child(old_product_name).get()
        
        if not product_ref:
            raise HTTPException(status_code=404, detail=f"Product '{old_product_name}' not found.")
        inventory_ref.child(new_product_name).set(product_ref)
        inventory_ref.child(old_product_name).delete()
        operation_id = log_admin_operation(
            token,
            "Rename Product Name",
            f"Renamed product name from '{old_product_name}' to '{new_product_name}'."
        )
        return {
            "message": f"Product name '{old_product_name}' renamed to '{new_product_name}' successfully.",
            "operation_id": operation_id
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to rename product name: {str(e)}")


#subscribe to the newsletter and get the updates
@app.post("/subscribe", summary="Subscribe to newsletter", description="Subscribe to the newsletter to receive updates.")
async def subscribe(email: str):
    try:
        ref = db.reference("subscribers")
        ref.push({"email": email})
        return {"message": "Subscribed successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to subscribe: {str(e)}")
    

# # Sale Routes
# @app.post("/sales", summary="Record a new sale", description="Record a sale by checking inventory availability and updating the inventory accordingly.")
# async def add_sale(sale: Sale):
#     try:
#         ref = db.reference("sales")
#         inventory_ref = db.reference("inventory")
#         inventory = inventory_ref.get()

#         for product in sale.products:
#             # Check if product exists in inventory and has sufficient quantity
#             for key, value in inventory.items() if inventory else []:
#                 if value["product_name"] == product.product_name:
#                     if value["quantity"] < product.quantity:
#                         raise HTTPException(status_code=400, detail=f"Insufficient inventory for {product.product_name}")
#                     updated_quantity = value["quantity"] - product.quantity
#                     inventory_ref.child(key).update({"quantity": updated_quantity})
#                     break
#             else:
#                 raise HTTPException(status_code=400, detail=f"{product.product_name} does not exist in inventory")

#         ref.push(sale.dict())
#         return {"message": "Sale added successfully"}
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=f"Failed to add sale: {str(e)}")
    
# @app.get("/sales/history", summary="Get sale history", description="Retrieve the history of all sales made with sale details.")
# async def get_sale_history():
#     try:
#         ref = db.reference("sales")
#         sales = ref.get()
#         if not sales:
#             return {"history": []}

#         history = []
#         for key, sale in sales.items():
#             history.append({
#                 "sale_id": key,
#                 "items": sale["products"],
#                 "grand_total": sale["total_amount"]
#             })

#         return {"history": history}
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=f"Failed to fetch sale history: {str(e)}")

# # Purchase Routes
# @app.post("/purchases", summary="Record a new purchase", description="Record a purchase by updating the inventory.")
# async def add_purchase(purchase: Sale):
#     try:
#         ref = db.reference("purchases")
#         inventory_ref = db.reference("inventory")
#         inventory = inventory_ref.get()

#         grand_total = sum(product.quantity * product.product_price for product in purchase.products)
#         for product in purchase.products:
#             # Update or add product in inventory
#             for key, value in inventory.items() if inventory else []:
#                 if value["product_name"] == product.product_name:
#                     updated_quantity = value["quantity"] + product.quantity
#                     inventory_ref.child(key).update({"quantity": updated_quantity})
#                     break
#             else:
#                 inventory_ref.push({
#                     "product_name": product.product_name,
#                     "product_price": product.product_price,
#                     "quantity": product.quantity
#                 })

#         ref.push({**purchase.dict(), "grand_total": grand_total})
#         return {"message": "Purchase added successfully", "grand_total": grand_total}
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=f"Failed to add purchase: {str(e)}")
    

# @app.get("/purchases/history", summary="Get purchase history", description="Retrieve the history of all purchases made with purchase details.")
# async def get_purchase_history():
#     try:
#         ref = db.reference("purchases")
#         purchases = ref.get()
#         if not purchases:
#             return {"history": []}

#         history = []
#         for key, purchase in purchases.items():
#             history.append({
#                 "purchase_id": key,
#                 "items": purchase["products"],
#                 "grand_total": purchase["grand_total"]
#             })

#         return {"history": history}
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=f"Failed to fetch purchase history: {str(e)}")

# from fastapi import FastAPI, Depends, HTTPException, UploadFile, File
# from firebase_admin import db, storage
# from typing import List
# import uuid

# app = FastAPI()

# @app.post(
#     "/admin/inventory/add", 
#     summary="Add a new product to the inventory", 
#     description="Add a new product along with details and upload images to Firebase."
# )
# async def add_product(
#     item: InventoryItem,
#     images: List[UploadFile] = File(...),
#     token: str = Depends(oauth2_scheme)
# ):
#     try:
#         # Validate admin token
#         admin_ref = db.reference("admins")
#         admin = admin_ref.child(token).get()
#         if not admin:
#             raise HTTPException(status_code=403, detail="Unauthorized access")

#         # Check if product already exists
#         inventory_ref = db.reference("inventory")
#         product_ref = inventory_ref.child(item.product_name)
#         if product_ref.get():
#             raise HTTPException(status_code=400, detail="Product with the given name already exists.")

#         # Upload images to Firebase Storage
#         image_urls = []
#         bucket = storage.bucket()
#         for index, image in enumerate(images):
#             if not image.content_type.startswith("image/"):
#                 raise HTTPException(status_code=400, detail="All uploaded files must be images.")
            
#             # Define storage path and file name
#             file_extension = image.filename.split('.')[-1]
#             storage_path = f"{item.product_name}_{index + 1}.{file_extension}"
            
#             # Upload to Firebase Storage
#             blob = bucket.blob(storage_path)
#             blob.upload_from_file(image.file)
#             blob.make_public()
#             image_urls.append(blob.public_url)

#         # Save product data to Realtime Database
#         product_data = {
#             "product_price": item.product_price,
#             "quantity": item.quantity,
#             "category": item.category,
#             "tags": item.tags,
#             "images": image_urls
#         }
#         product_ref.set(product_data)

#         # Add category if not already present
#         categories_ref = db.reference("categories")
#         if not categories_ref.child(item.category).get():
#             categories_ref.child(item.category).set({})
#         categories_ref.child(item.category).child(item.product_name).set(True)

#         # Add tags if not already present
#         tags_ref = db.reference("tags")
#         for tag in item.tags:
#             if not tags_ref.child(tag).get():
#                 tags_ref.child(tag).set({})
#             tags_ref.child(tag).child(item.product_name).set(True)

#         operation_id = log_admin_operation(
#             token,
#             "Add Product",
#             f"Added product '{item.product_name}' to the inventory."
#         )
#         return {"message": f"Product '{item.product_name}' added successfully.", "operation_id": operation_id}

#     except Exception as e:
#         raise HTTPException(status_code=500, detail=f"Failed to add product: {str(e)}")


# # Define the InventoryItem class
# class InventoryItem:
#     product_name: str
#     product_price: float
#     quantity: int
#     category: str
#     tags: List[str]

@app.get("/")
def root():
    return {"message": "Welcome to the Growmore E-commerce API By BluOrigin Team"}