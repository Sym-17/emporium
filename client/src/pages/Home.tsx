import panjabiImage from "../assets/panjabi_sailor.jpg";
import { HeartIcon, ShoppingBagIcon } from "@heroicons/react/24/outline";
import { useCart } from "../components/useCart";

//comment

type Product = {
  id: string;
  productName: string;
  category: string;
  subCategory: string;
  price: string;
  description: string;
};

export default function Home() {
  const allProductsString = localStorage.getItem("product");
  const allProducts = allProductsString ? JSON.parse(allProductsString) : [];

  const {
    incCartProductNumber,
    decCartProductNumber,
    cartedProductsIDs,
    addCartProduct,
    removeCartProduct,
    allCartedProducts,
  } = useCart();

  const addToCart = (productToAdd: Product) => {
    let duplicate = false;
    allCartedProducts.forEach((product) => {
      if (product.id === productToAdd.id) {
        duplicate = true;
      }
    });
    if (!duplicate) {
      addCartProduct(productToAdd);
      incCartProductNumber();
      cartedProductsIDs.set(productToAdd.id, true);
    }
  };

  const deleteFromCart = (productToRemove: Product) => {
    allCartedProducts.forEach((product) => {
      if (product.id === productToRemove.id) {
        cartedProductsIDs.delete(productToRemove.id);
        decCartProductNumber();
        removeCartProduct(productToRemove);
      }
    });
  };

  return (
    <div className="flex flex-col gap-4 items-center pt-10 pb-10 pl-5 pr-5 lg:pl-20 lg:pr-20">
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5 gap-8">
        {allProducts.map((product: Product) => {
          return (
            <div className="flex flex-col gap-2" key={product.id}>
              <img src={panjabiImage} alt="" />
              <div className="flex justify-between">
                <div>
                  <p className="text-xl text-[#3f3d56]">
                    {product.productName}
                  </p>
                  <p>{product.price}</p>
                </div>
                <div className="flex gap-4">
                  <HeartIcon className="w-6 text-[#3f3d56] cursor-pointer hover:text-[#536DFE]" />
                  <ShoppingBagIcon
                    className={`w-6 cursor-pointer hover:text-[#536DFE] ${
                      cartedProductsIDs.get(product.id)
                        ? "fill-[#536DFE] text-[#536DFE] hover:fill-white"
                        : "text-[#3f3d56]"
                    }`}
                    onClick={
                      cartedProductsIDs.get(product.id)
                        ? () => deleteFromCart(product)
                        : () => addToCart(product)
                    }
                  />
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
